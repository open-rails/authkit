package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUserGET(svc core.Provider) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("user_id")
		u, err := svc.AdminGetUser(c.Request.Context(), id)
		if err != nil || u == nil {
			ginutil.NotFound(c, "not_found")
			return
		}
		c.JSON(http.StatusOK, u)
	}
}
