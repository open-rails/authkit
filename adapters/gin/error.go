package authkitgin

import (
	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit/iam"
)

// Error writes err as AuthKit's error envelope, with the catalog status for its
// code, and aborts the chain. A non-AuthKit error is written as 500
// internal_error.
func Error(c *gin.Context, err error) {
	iam.WriteError(c.Writer, err)
	c.Abort()
}
