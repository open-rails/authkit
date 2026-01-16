package handlers

import (
	"net/http"
	"strconv"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleAdminDeletedUsersListGET lists soft-deleted users (deleted_at IS NOT NULL).
func HandleAdminDeletedUsersListGET(svc core.Provider) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
		filter := c.DefaultQuery("filter", "All users")
		search := c.DefaultQuery("search", "")

		result, err := svc.AdminListUsers(c.Request.Context(), page, size, filter, search, true)
		if err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_list_deleted_users", err, "failed to list deleted users")
			return
		}
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
