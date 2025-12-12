package handlers

import (
	"net/http"
	"strconv"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// ListResponse is a Stripe-style list response for admin users
type ListResponse struct {
	Object  string           `json:"object"`
	Data    []core.AdminUser `json:"data"`
	Total   int64            `json:"total"`
	Limit   int              `json:"limit"`
	Offset  int              `json:"offset"`
	HasMore bool             `json:"has_more"`
}

func HandleAdminUsersListGET(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsList) {
			ginutil.TooMany(c)
			return
		}
		result, err := svc.AdminListUsers(c.Request.Context(), page, size)
		if err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_list_users", err, "failed to list users")
			return
		}
		// Return Stripe-style list response
		hasMore := int64(result.Offset+result.Limit) < result.Total
		c.JSON(http.StatusOK, ListResponse{
			Object:  "list",
			Data:    result.Users,
			Total:   result.Total,
			Limit:   result.Limit,
			Offset:  result.Offset,
			HasMore: hasMore,
		})
	}
}
