package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	operatorv1alpha1 "github.com/fzymgc-house/router-hosts/api/operator/v1alpha1"
	"github.com/fzymgc-house/router-hosts/internal/operator"
)

func main() {
	var (
		metricsAddr          string
		healthProbeAddr      string
		enableLeaderElection bool
		serverAddr           string
		certPath             string
		keyPath              string
		caCertPath           string
		defaultIngressIP     string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address the metrics endpoint binds to")
	flag.StringVar(&healthProbeAddr, "health-probe-bind-address", ":8081", "Address the health probes bind to")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for HA deployments")
	flag.StringVar(&serverAddr, "server-address", "localhost:50051", "router-hosts gRPC server address")
	flag.StringVar(&certPath, "tls-cert", "", "Path to client TLS certificate for mTLS")
	flag.StringVar(&keyPath, "tls-key", "", "Path to client TLS private key for mTLS")
	flag.StringVar(&caCertPath, "tls-ca", "", "Path to CA certificate for server verification")
	flag.StringVar(&defaultIngressIP, "default-ingress-ip", "", "Default IP for hosts extracted from IngressRoutes")
	flag.Parse()

	// Set up structured slog logging and bridge to controller-runtime's logr.
	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(slogHandler)
	slog.SetDefault(logger)
	ctrl.SetLogger(logr.FromSlogHandler(slogHandler))

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		logger.Error("failed to add client-go scheme", "error", err)
		os.Exit(1)
	}
	if err := operatorv1alpha1.AddToScheme(scheme); err != nil {
		logger.Error("failed to add operator scheme", "error", err)
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: healthProbeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "router-hosts-operator.fzymgc.house",
	})
	if err != nil {
		logger.Error("unable to create manager", "error", err)
		os.Exit(1)
	}

	if defaultIngressIP == "" {
		logger.Warn("--default-ingress-ip is empty; IngressRoute controller will create hosts with no IP")
	}

	// Create gRPC client for communicating with router-hosts server.
	hostClient, err := operator.NewGRPCHostClient(serverAddr, certPath, keyPath, caCertPath)
	if err != nil {
		logger.Error("unable to create gRPC host client", "error", err)
		os.Exit(1)
	}
	defer func() {
		if cerr := hostClient.Close(); cerr != nil {
			logger.Error("failed to close gRPC host client", "error", cerr)
		}
	}()

	// Register HostMapping controller.
	if err := (&operator.HostMappingReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		HostClient: hostClient,
		Log:        logger.With("controller", "hostmapping"),
	}).SetupWithManager(mgr); err != nil {
		logger.Error("unable to create HostMapping controller", "error", err)
		os.Exit(1)
	}

	// Register IngressRoute controller.
	if err := (&operator.IngressRouteReconciler{
		Client:      mgr.GetClient(),
		HostClient:  hostClient,
		Log:         logger.With("controller", "ingressroute"),
		DefaultIP:   defaultIngressIP,
		DefaultTags: []string{"kubernetes"},
	}).SetupWithManager(mgr); err != nil {
		logger.Error("unable to create IngressRoute controller", "error", err)
		os.Exit(1)
	}

	// Health probes.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error("unable to set up health check", "error", err)
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error("unable to set up ready check", "error", err)
		os.Exit(1)
	}

	logger.Info("starting operator",
		"metricsAddr", metricsAddr,
		"healthProbeAddr", healthProbeAddr,
		"leaderElection", enableLeaderElection,
		"serverAddr", serverAddr,
	)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error("manager exited with error", "error", err)
		os.Exit(1)
	}
}
