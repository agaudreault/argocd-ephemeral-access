package backend_test

import (
	"encoding/json"
	"fmt"
	"testing"

	api "github.com/argoproj-labs/ephemeral-access/api/ephemeral-access/v1alpha1"
	"github.com/argoproj-labs/ephemeral-access/internal/backend"
	"github.com/argoproj-labs/ephemeral-access/test/mocks"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newAccessRequest(name, namespace, appName, roleName, subject string) *api.AccessRequest {
	return &api.AccessRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AccessRequest",
			APIVersion: "v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: api.AccessRequestSpec{
			Duration:         metav1.Duration{},
			RoleTemplateName: roleName,
			Application: api.TargetApplication{
				Name:      appName,
				Namespace: namespace,
			},
			Subject: api.Subject{
				Username: subject,
			},
		},
	}
}

func headers(namespace, username, groups, appName, projName string) []any {
	return []any{
		fmt.Sprintf("Argocd-Namespace: %s", namespace),
		fmt.Sprintf("Argocd-Username: %s", username),
		fmt.Sprintf("Argocd-User-Groups: %s", groups),
		fmt.Sprintf("Argocd-Application-Name: %s", appName),
		fmt.Sprintf("Argocd-Project-Name: %s", projName),
	}
}

func TestGetAccessRequest(t *testing.T) {
	type fixture struct {
		api     humatest.TestAPI
		service *mocks.MockService
		logger  *mocks.MockLogger
	}
	setup := func(t *testing.T) *fixture {
		_, api := humatest.New(t)
		service := mocks.NewMockService(t)
		logger := mocks.NewMockLogger(t)
		handler := backend.NewAPIHandler(service, logger)
		backend.RegisterRoutes(api, handler)
		return &fixture{
			api:     api,
			service: service,
			logger:  logger,
		}
	}
	t.Run("will return access request successfully", func(t *testing.T) {
		// Given
		f := setup(t)
		arName := "some-ar"
		nsName := "some-namespace"
		username := "some-user"
		appName := "some-app"
		ar := newAccessRequest(arName, nsName, appName, "some-role", username)
		f.service.EXPECT().GetAccessRequest(mock.Anything, arName, nsName).
			Return(ar, nil)
		headers := headers("argocd-ns", username, "group1", appName, "some-project")

		// When
		resp := f.api.Get("/accessrequests/some-ar?namespace=some-namespace", headers...)

		// Then
		assert.NotNil(t, resp)
		assert.Equal(t, 200, resp.Result().StatusCode)
		var respBody backend.AccessRequestResponseBody
		err := json.Unmarshal(resp.Body.Bytes(), &respBody)
		assert.NoError(t, err)
		assert.Equal(t, arName, respBody.Name)
		assert.Equal(t, username, respBody.Username)
	})
	t.Run("will return 500 on service error", func(t *testing.T) {
		// Given
		f := setup(t)
		arName := "some-ar"
		nsName := "some-namespace"
		username := "some-user"
		appName := "some-app"
		f.service.EXPECT().GetAccessRequest(mock.Anything, arName, nsName).
			Return(nil, fmt.Errorf("some-error"))
		f.logger.EXPECT().Error(mock.Anything, mock.Anything)
		headers := headers("argocd-ns", username, "group1", appName, "some-project")

		// When
		resp := f.api.Get("/accessrequests/some-ar?namespace=some-namespace", headers...)

		// Then
		assert.NotNil(t, resp)
		assert.Equal(t, 500, resp.Result().StatusCode)
	})
	t.Run("will return 404 if access request not found", func(t *testing.T) {
		// Given
		f := setup(t)
		arName := "some-ar"
		nsName := "some-namespace"
		username := "some-user"
		appName := "some-app"
		f.service.EXPECT().GetAccessRequest(mock.Anything, arName, nsName).
			Return(nil, nil)
		headers := headers("argocd-ns", username, "group1", appName, "some-project")

		// When
		resp := f.api.Get("/accessrequests/some-ar?namespace=some-namespace", headers...)

		// Then
		assert.NotNil(t, resp)
		assert.Equal(t, 404, resp.Result().StatusCode)
	})

}
