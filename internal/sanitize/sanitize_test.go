package sanitize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommentField_CollapsesLF(t *testing.T) {
	got := CommentField("line one\nline two")
	assert.Equal(t, "line one line two", got)
}

func TestCommentField_CollapsesCR(t *testing.T) {
	got := CommentField("line one\rline two")
	assert.Equal(t, "line one line two", got)
}

func TestCommentField_LeavesOtherBytes(t *testing.T) {
	got := CommentField("héllo wörld — 日本語")
	assert.Equal(t, "héllo wörld — 日本語", got)
}
