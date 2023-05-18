package xerrors

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestNewDSError(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.SetBasicAuth("ximager", "ximager1")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := NewDSError(c, DSErrCodeBlobUnknown)
	assert.NoError(t, err)
}
