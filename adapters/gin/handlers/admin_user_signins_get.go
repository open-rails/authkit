package handlers

import (
	"net/http"
	"strconv"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUserSigninsGET(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("user_id")
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsList) {
			ginutil.TooMany(c)
			return
		}
		items, err := svc.AdminGetUserSignins(c.Request.Context(), id, page, size)
		if err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_list_signins", err, "failed to list user signins")
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": items, "page": page, "page_size": size})
	}
}
