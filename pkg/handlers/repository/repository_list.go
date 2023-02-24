package repository

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"

	"github.com/ximager/ximager/pkg/consts"
	"github.com/ximager/ximager/pkg/dal/dao"
	"github.com/ximager/ximager/pkg/types"
	"github.com/ximager/ximager/pkg/xerrors"
)

// ListRepository handles the list repository request
func (h *handlers) ListRepository(c echo.Context) error {
	ctx := c.Request().Context()

	var req types.ListRepositoryRequest
	err := c.Bind(&req)
	if err != nil {
		log.Error().Err(err).Msg("Bind request body failed")
		return xerrors.NewHTTPError(c, xerrors.HTTPErrCodeBadRequest, err.Error())
	}
	err = c.Validate(&req)
	if err != nil {
		log.Error().Err(err).Msg("Validate request body failed")
		return xerrors.NewHTTPError(c, xerrors.HTTPErrCodeBadRequest, err.Error())
	}

	repositoryService := dao.NewRepositoryService()
	repositories, err := repositoryService.ListRepository(ctx, req)

	var repositoryIDs []uint
	for _, repository := range repositories {
		repositoryIDs = append(repositoryIDs, repository.ID)
	}
	artifactService := dao.NewArtifactService()
	artifactCountRef, err := artifactService.CountByRepository(ctx, repositoryIDs)
	if err != nil {
		log.Error().Err(err).Msg("Count artifact from db failed")
		return xerrors.NewHTTPError(c, xerrors.HTTPErrCodeInternalError, err.Error())
	}

	var resp []any
	for _, repository := range repositories {
		resp = append(resp, types.RepositoryItem{
			ID:            repository.ID,
			Name:          repository.Name,
			ArtifactCount: artifactCountRef[repository.ID],
			CreatedAt:     repository.CreatedAt.Format(consts.DefaultTimePattern),
			UpdatedAt:     repository.UpdatedAt.Format(consts.DefaultTimePattern),
		})
	}
	total, err := repositoryService.CountRepository(ctx, req)
	if err != nil {
		log.Error().Err(err).Msg("Count repository from db failed")
		return xerrors.NewHTTPError(c, xerrors.HTTPErrCodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, types.CommonList{Total: total, Items: resp})
}
