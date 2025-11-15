package handlers

import (
	"net/http"
	"strconv"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUsersListGET(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsList) {
			ginutil.TooMany(c)
			return
		}
		users, err := svc.AdminListUsers(c.Request.Context(), page, size)
		if err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_list_users", err, "failed to list users")
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": users, "page": page, "page_size": size})
	}
}
