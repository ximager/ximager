package artifacts

import (
	"context"
	"time"

	"github.com/ximager/ximager/pkg/dal/models"
	"github.com/ximager/ximager/pkg/dal/query"
	"gorm.io/gorm"
)

// ArtifactService is the interface that provides the artifact service methods.
type ArtifactService interface {
	// Save save a new artifact if conflict update.
	Save(ctx context.Context, artifact *models.Artifact) (*models.Artifact, error)
	// Get gets the artifact with the specified artifact ID.
	Get(ctx context.Context, id uint) (*models.Artifact, error)
	// GetByDigest gets the artifact with the specified digest.
	GetByDigest(ctx context.Context, repository, digest string) (*models.Artifact, error)
	// DeleteByDigest deletes the artifact with the specified digest.
	DeleteByDigest(ctx context.Context, repository, digest string) error
	// AssociateBlobs associates the blobs with the artifact.
	AssociateBlobs(ctx context.Context, artifact *models.Artifact, blobs []*models.Blob) error
	// Incr increases the pull times of the artifact.
	Incr(ctx context.Context, id uint) error
}

type artifactService struct {
	tx *query.Query
}

// NewArtifactService creates a new artifact service.
func NewArtifactService(txs ...*query.Query) ArtifactService {
	tx := query.Q
	if len(txs) > 0 {
		tx = txs[0]
	}
	return &artifactService{
		tx: tx,
	}
}

// Save save a new artifact if conflict update.
func (s *artifactService) Save(ctx context.Context, artifact *models.Artifact) (*models.Artifact, error) {
	err := s.tx.Artifact.WithContext(ctx).Save(artifact)
	if err != nil {
		return nil, err
	}
	return artifact, nil
}

// Get gets the artifact with the specified artifact ID.
func (s *artifactService) Get(ctx context.Context, id uint) (*models.Artifact, error) {
	artifact, err := s.tx.Artifact.WithContext(ctx).Where(s.tx.Artifact.ID.Eq(id)).First()
	if err != nil {
		return nil, err
	}
	return artifact, nil
}

// GetByDigest gets the artifact with the specified digest.
func (s *artifactService) GetByDigest(ctx context.Context, repository, digest string) (*models.Artifact, error) {
	artifact, err := s.tx.Artifact.WithContext(ctx).Where(s.tx.Artifact.Digest.Eq(digest)).First()
	if err != nil {
		return nil, err
	}
	return artifact, nil
}

// DeleteByDigest deletes the artifact with the specified digest.
func (s *artifactService) DeleteByDigest(ctx context.Context, repository, digest string) error {
	err := s.tx.Transaction(func(tx *query.Query) error {
		artifact, err := tx.Artifact.WithContext(ctx).Where(tx.Artifact.Digest.Eq(digest)).First()
		if err != nil {
			return err
		}
		_, err = tx.Artifact.WithContext(ctx).Where(tx.Artifact.Digest.Eq(digest)).Delete()
		if err != nil {
			return err
		}
		_, err = tx.Tag.WithContext(ctx).Where(tx.Tag.ArtifactID.Eq(artifact.ID)).Delete()
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *artifactService) AssociateBlobs(ctx context.Context, artifact *models.Artifact, blobs []*models.Blob) error {
	return s.tx.Artifact.Blobs.Model(artifact).Append(blobs...)
}

// Incr increases the pull times of the artifact.
func (s *artifactService) Incr(ctx context.Context, id uint) error {
	_, err := s.tx.Artifact.WithContext(ctx).Where(s.tx.Tag.ID.Eq(id)).
		UpdateColumns(map[string]interface{}{
			"pull_times": gorm.Expr("pull_times + ?", 1),
			"last_pull":  time.Now(),
		})
	if err != nil {
		return err
	}
	return nil
}
