//! Integration tests for DNS providers using wiremock
//!
//! These tests verify the DNS provider implementations against mock HTTP servers,
//! ensuring correct API contract handling for both success and error cases.

use router_hosts::server::acme::dns_provider::{
    CloudflareProvider, DnsProvider, DnsProviderError, WebhookProvider,
};
use std::collections::HashMap;
use std::time::Duration;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ============================================================================
// Cloudflare Provider Tests
// ============================================================================

mod cloudflare {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mock_server = MockServer::start().await;

        // Mock successful record creation
        Mock::given(method("POST"))
            .and(path("/zones/zone123/dns_records"))
            .and(header("authorization", "Bearer test-token"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": {
                    "id": "record-abc123"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = CloudflareProvider::new_with_base_url(
            "test-token".to_string(),
            "zone123".to_string(),
            mock_server.uri(),
        )
        .expect("valid provider");

        let record = provider
            .create_txt_record("_acme-challenge.example.com", "test-digest")
            .await
            .expect("should create record");

        assert_eq!(record.record_id, "record-abc123");
        assert_eq!(record.name, "_acme-challenge.example.com");
    }

    #[tokio::test]
    async fn test_create_txt_record_api_error() {
        let mock_server = MockServer::start().await;

        // Mock API error response
        Mock::given(method("POST"))
            .and(path("/zones/zone123/dns_records"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "success": false,
                "errors": [
                    {"code": 10000, "message": "Authentication error"}
                ],
                "result": null
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = CloudflareProvider::new_with_base_url(
            "test-token".to_string(),
            "zone123".to_string(),
            mock_server.uri(),
        )
        .expect("valid provider");

        let result = provider
            .create_txt_record("_acme-challenge.example.com", "test-digest")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DnsProviderError::Api { status: 403, .. }));
        assert!(err.to_string().contains("Authentication error"));
    }

    #[tokio::test]
    async fn test_delete_txt_record_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/zones/zone123/dns_records/record-abc123"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": {"id": "record-abc123"}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = CloudflareProvider::new_with_base_url(
            "test-token".to_string(),
            "zone123".to_string(),
            mock_server.uri(),
        )
        .expect("valid provider");

        let record = router_hosts::server::acme::dns_provider::DnsRecord {
            record_id: "record-abc123".to_string(),
            name: "_acme-challenge.example.com".to_string(),
        };

        let result = provider.delete_txt_record(&record).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_txt_record_not_found_is_ok() {
        let mock_server = MockServer::start().await;

        // 404 is acceptable for delete (record already gone)
        Mock::given(method("DELETE"))
            .and(path("/zones/zone123/dns_records/record-abc123"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = CloudflareProvider::new_with_base_url(
            "test-token".to_string(),
            "zone123".to_string(),
            mock_server.uri(),
        )
        .expect("valid provider");

        let record = router_hosts::server::acme::dns_provider::DnsRecord {
            record_id: "record-abc123".to_string(),
            name: "_acme-challenge.example.com".to_string(),
        };

        let result = provider.delete_txt_record(&record).await;
        assert!(result.is_ok(), "404 should be treated as success");
    }

    #[tokio::test]
    async fn test_zone_auto_detection_success() {
        let mock_server = MockServer::start().await;

        // First query for full domain - no match
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "sub.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Second query for parent domain - found
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [{
                    "id": "zone-found",
                    "name": "example.com"
                }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = CloudflareProvider::with_auto_zone_and_base_url(
            "test-token".to_string(),
            "sub.example.com",
            mock_server.uri(),
        )
        .await
        .expect("should find zone");

        assert_eq!(provider.zone_id(), "zone-found");
    }

    #[tokio::test]
    async fn test_zone_auto_detection_not_found() {
        let mock_server = MockServer::start().await;

        // All queries return empty
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .mount(&mock_server)
            .await;

        let result = CloudflareProvider::with_auto_zone_and_base_url(
            "test-token".to_string(),
            "sub.example.com",
            mock_server.uri(),
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DnsProviderError::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn test_zone_exact_match_validation() {
        let mock_server = MockServer::start().await;

        // Return multiple zones - only exact match should be used
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [
                    {"id": "zone-wrong", "name": "other.example.com"},
                    {"id": "zone-correct", "name": "example.com"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = CloudflareProvider::with_auto_zone_and_base_url(
            "test-token".to_string(),
            "example.com",
            mock_server.uri(),
        )
        .await
        .expect("should find exact match");

        assert_eq!(provider.zone_id(), "zone-correct");
    }
}

// ============================================================================
// Webhook Provider Tests
// ============================================================================

mod webhook {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/dns/create"))
            .and(header("content-type", "application/json"))
            .and(header("authorization", "Bearer webhook-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "webhook-record-123"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            "Bearer webhook-token".to_string(),
        );

        let provider = WebhookProvider::new(
            format!("{}/dns/create", mock_server.uri()),
            format!("{}/dns/delete/{{record_id}}", mock_server.uri()),
            headers,
            Duration::from_secs(10),
        )
        .expect("valid provider");

        let record = provider
            .create_txt_record("_acme-challenge.example.com", "test-digest")
            .await
            .expect("should create record");

        assert_eq!(record.record_id, "webhook-record-123");
        assert_eq!(record.name, "_acme-challenge.example.com");
    }

    #[tokio::test]
    async fn test_create_txt_record_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/dns/create"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal server error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = WebhookProvider::new(
            format!("{}/dns/create", mock_server.uri()),
            format!("{}/dns/delete/{{record_id}}", mock_server.uri()),
            HashMap::new(),
            Duration::from_secs(10),
        )
        .expect("valid provider");

        let result = provider
            .create_txt_record("_acme-challenge.example.com", "test-digest")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DnsProviderError::Api { status: 500, .. }));
    }

    #[tokio::test]
    async fn test_delete_txt_record_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/dns/delete/webhook-record-123"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = WebhookProvider::new(
            format!("{}/dns/create", mock_server.uri()),
            format!("{}/dns/delete/{{record_id}}", mock_server.uri()),
            HashMap::new(),
            Duration::from_secs(10),
        )
        .expect("valid provider");

        let record = router_hosts::server::acme::dns_provider::DnsRecord {
            record_id: "webhook-record-123".to_string(),
            name: "_acme-challenge.example.com".to_string(),
        };

        let result = provider.delete_txt_record(&record).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_txt_record_not_found_is_ok() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/dns/delete/webhook-record-123"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = WebhookProvider::new(
            format!("{}/dns/create", mock_server.uri()),
            format!("{}/dns/delete/{{record_id}}", mock_server.uri()),
            HashMap::new(),
            Duration::from_secs(10),
        )
        .expect("valid provider");

        let record = router_hosts::server::acme::dns_provider::DnsRecord {
            record_id: "webhook-record-123".to_string(),
            name: "_acme-challenge.example.com".to_string(),
        };

        let result = provider.delete_txt_record(&record).await;
        assert!(result.is_ok(), "404 should be treated as success");
    }

    #[tokio::test]
    async fn test_custom_headers_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/dns/create"))
            .and(header("x-api-key", "secret123"))
            .and(header("x-tenant-id", "tenant-abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "record-123"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut headers = HashMap::new();
        headers.insert("X-API-Key".to_string(), "secret123".to_string());
        headers.insert("X-Tenant-ID".to_string(), "tenant-abc".to_string());

        let provider = WebhookProvider::new(
            format!("{}/dns/create", mock_server.uri()),
            format!("{}/dns/delete/{{record_id}}", mock_server.uri()),
            headers,
            Duration::from_secs(10),
        )
        .expect("valid provider");

        let result = provider
            .create_txt_record("_acme-challenge.example.com", "test-digest")
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_malformed_json_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/dns/create"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = WebhookProvider::new(
            format!("{}/dns/create", mock_server.uri()),
            format!("{}/dns/delete/{{record_id}}", mock_server.uri()),
            HashMap::new(),
            Duration::from_secs(10),
        )
        .expect("valid provider");

        let result = provider
            .create_txt_record("_acme-challenge.example.com", "test-digest")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DnsProviderError::Parse(_)));
    }
}
