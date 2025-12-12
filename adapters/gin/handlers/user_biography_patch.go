package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleUserBiographyPATCH(svc core.Provider) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid, _ := c.Get("auth.user_id")
		userID, _ := uid.(string)
		var body struct {
			Biography *string `json:"biography"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		if body.Biography != nil {
			s := strings.TrimSpace(*body.Biography)
			if len(s) > 2000 {
				s = s[:2000]
			}
			body.Biography = &s
		}
		if err := svc.UpdateBiography(c.Request.Context(), userID, body.Biography); err != nil {
			ginutil.BadRequest(c, "failed_to_update_biography")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
