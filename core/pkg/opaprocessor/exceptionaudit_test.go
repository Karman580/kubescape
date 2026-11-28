package opaprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildExceptionAudit(t *testing.T) {
	expiredAt := time.Now().Add(-time.Hour)
	matchedException := auditException("matched-exception", "C-0001", nil)
	unusedException := auditException("unused-exception", "C-0002", nil)
	expiredException := auditException("expired-exception", "C-0003", &expiredAt)
	invalidControlException := auditException("invalid-control-exception", "C-9999", nil)

	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "default",
		},
	})

	audit := buildExceptionAudit(
		[]armotypes.PostureExceptionPolicy{matchedException, unusedException, expiredException, invalidControlException},
		[]armotypes.PostureExceptionPolicy{matchedException, unusedException, invalidControlException},
		map[string]resourcesresults.Result{
			resource.GetID(): {
				ResourceID: resource.GetID(),
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0001",
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Name:      "rule-a",
								Exception: []armotypes.PostureExceptionPolicy{matchedException},
							},
						},
					},
				},
			},
		},
		cautils.NewMapResourceCatalog(map[string]workloadinterface.IMetadata{resource.GetID(): resource}),
		&cautils.Policies{
			Controls: map[string]reporthandling.Control{
				"C-0001": {ControlID: "C-0001"},
				"C-0002": {ControlID: "C-0002"},
				"C-0003": {ControlID: "C-0003"},
			},
		},
		exceptions.NewProcessor(),
		nil,
		nil, // no framework context
	)

	require.NotNil(t, audit)
	assert.True(t, audit.Generated)
	assert.Equal(t, 4, audit.Summary.Total)
	assert.Equal(t, 3, audit.Summary.Active)
	assert.Equal(t, 1, audit.Summary.Expired)
	assert.Equal(t, 1, audit.Summary.Matched)
	assert.Equal(t, 1, audit.Summary.Unused)
	assert.Equal(t, 1, audit.Summary.InvalidControl)

	items := map[string]cautils.ExceptionAuditItem{}
	for _, item := range audit.Items {
		items[item.Name] = item
	}

	assert.Equal(t, exceptionAuditStatusMatched, items["matched-exception"].Status)
	assert.Equal(t, 1, items["matched-exception"].MatchCount)
	require.Len(t, items["matched-exception"].MatchedResources, 1)
	assert.Equal(t, "Deployment", items["matched-exception"].MatchedResources[0].Kind)
	assert.Equal(t, "default", items["matched-exception"].MatchedResources[0].Namespace)
	assert.Equal(t, "nginx", items["matched-exception"].MatchedResources[0].Name)
	assert.Equal(t, "C-0001", items["matched-exception"].MatchedResources[0].ControlID)
	assert.Equal(t, "rule-a", items["matched-exception"].MatchedResources[0].RuleName)

	assert.Equal(t, exceptionAuditStatusUnused, items["unused-exception"].Status)
	assert.Equal(t, exceptionAuditStatusExpired, items["expired-exception"].Status)
	assert.True(t, items["expired-exception"].Expired)
	assert.Equal(t, exceptionAuditStatusInvalidControl, items["invalid-control-exception"].Status)
	assert.Equal(t, []string{"C-9999"}, items["invalid-control-exception"].InvalidControls)
}

// Regression for issue-3366: an exception that exists solely to suppress a
// manual-review control has no resourcesresults.Result entries at all (manual
// controls produce none), so the audit must be told about the match through
// manualControlMatches instead - otherwise it reports the exception as unused
// even though applyExceptionsToManualControls actively applied it.
func TestBuildExceptionAuditCountsManualControlMatches(t *testing.T) {
	manualOnlyException := auditException("manual-control-exception", "C-0286", nil)

	audit := buildExceptionAudit(
		[]armotypes.PostureExceptionPolicy{manualOnlyException},
		[]armotypes.PostureExceptionPolicy{manualOnlyException},
		nil, // no resource-backed results at all
		nil,
		nil,
		exceptions.NewProcessor(),
		[]manualControlExceptionMatch{
			{exception: manualOnlyException, controlID: "C-0286"},
		},
		nil, // no framework context
	)

	require.NotNil(t, audit)
	require.Len(t, audit.Items, 1)
	item := audit.Items[0]

	assert.Equal(t, exceptionAuditStatusMatched, item.Status, "an exception that suppressed a manual control must not be reported as unused")
	assert.Equal(t, 1, item.MatchCount)
	require.Len(t, item.MatchedResources, 1)
	assert.Equal(t, "C-0286", item.MatchedResources[0].ControlID)
	assert.Equal(t, 1, audit.Summary.Matched)
	assert.Equal(t, 0, audit.Summary.Unused)
}

// End-to-end regression for issue-3366: runs the real updateResults path (via
// a manual-review-only control summary and AuditExceptions enabled) and checks
// the resulting ExceptionAudit, rather than calling buildExceptionAudit directly.
func TestUpdateResults_ExceptionAuditCountsManualControlMatch(t *testing.T) {
	manualException := auditException("manual-control-exception", "C-0286", nil)

	session := cautils.NewOPASessionObjMock()
	session.AuditExceptions = true
	session.Exceptions = []armotypes.PostureExceptionPolicy{manualException}
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		"C-0286": reportsummary.ControlSummary{
			ControlID: "C-0286",
			StatusInfo: apis.StatusInfo{
				InnerStatus: apis.StatusSkipped,
				SubStatus:   apis.SubStatusManualReview,
			},
		},
	}

	opap := &OPAProcessor{OPASessionObj: session}
	opap.updateResults(context.Background())

	require.NotNil(t, opap.ExceptionAudit)
	require.Len(t, opap.ExceptionAudit.Items, 1)
	item := opap.ExceptionAudit.Items[0]
	assert.Equal(t, exceptionAuditStatusMatched, item.Status, "the manual control's exception must not be reported as unused")
	assert.Equal(t, 1, item.MatchCount)

	ctrl := opap.Report.SummaryDetails.Controls["C-0286"]
	assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status(), "sanity check: the exception did actually suppress the manual control")
}

func TestBuildExceptionAuditTreatsRegexControlAsValid(t *testing.T) {
	regexException := auditException("regex-exception", "C-000[12]", nil)

	audit := buildExceptionAudit(
		[]armotypes.PostureExceptionPolicy{regexException},
		[]armotypes.PostureExceptionPolicy{regexException},
		nil,
		nil,
		&cautils.Policies{
			Controls: map[string]reporthandling.Control{
				"C-0001": {ControlID: "C-0001"},
			},
		},
		exceptions.NewProcessor(),
		nil,
		nil, // no framework context
	)

	require.NotNil(t, audit)
	require.Len(t, audit.Items, 1)
	assert.Empty(t, audit.Items[0].InvalidControls)
	assert.Equal(t, exceptionAuditStatusUnused, audit.Items[0].Status)
}

func TestBuildExceptionAuditDoesNotCollapseDuplicateNamesWithDifferentGUIDs(t *testing.T) {
	firstException := auditExceptionWithGUID("guid-1", "dup-name", "C-0001", nil)
	secondException := auditExceptionWithGUID("guid-2", "dup-name", "C-0002", nil)

	audit := buildExceptionAudit(
		[]armotypes.PostureExceptionPolicy{firstException, secondException},
		[]armotypes.PostureExceptionPolicy{firstException, secondException},
		nil,
		nil,
		&cautils.Policies{
			Controls: map[string]reporthandling.Control{
				"C-0001": {ControlID: "C-0001"},
				"C-0002": {ControlID: "C-0002"},
			},
		},
		exceptions.NewProcessor(),
		nil,
		nil, // no framework context
	)

	require.NotNil(t, audit)
	require.Len(t, audit.Items, 2)
	assert.Equal(t, 2, audit.Summary.Total)
	assert.Equal(t, 2, audit.Summary.Active)

	var gotControlIDs []string
	for _, item := range audit.Items {
		assert.Equal(t, "dup-name", item.Name)
		require.Len(t, item.ControlIDs, 1)
		gotControlIDs = append(gotControlIDs, item.ControlIDs[0])
	}
	assert.ElementsMatch(t, []string{"C-0001", "C-0002"}, gotControlIDs)
}

// Exceptions from --exceptions files and SecurityException CRDs have no GUID, and
// CRD-derived names ("<name>/<controlID>") are only unique per namespace. Every
// loaded exception must keep its own matches whatever copies the exceptions
// processor attaches to a rule: copies narrowed to the matching posture policies,
// resource-scoped copies of scope-less exceptions, and one copy per matching
// designator when resource selectors overlap.
func TestUpdateResults_ExceptionAuditAttributesMatchesToTheirSource(t *testing.T) {
	expiredAt := time.Now().Add(-time.Hour)
	nginx := []identifiers.PortalDesignator{auditDesignator("kind", "Deployment", "namespace", "default", "name", "nginx")}
	oldApp := []identifiers.PortalDesignator{auditDesignator("kind", "Deployment", "namespace", "default", "name", "old-app")}
	// Both designators match default/nginx, so each exception is attached twice.
	overlapping := []identifiers.PortalDesignator{auditDesignator("kind", "Deployment"), auditDesignator("namespace", "default")}

	for _, tc := range []struct {
		name       string
		exceptions []armotypes.PostureExceptionPolicy
		// want maps each item's control IDs to "status/matchCount". matchCount
		// counts every copy attached to a rule, as for a single exception.
		want map[string]string
	}{
		{
			name: "overlapping resource selectors",
			exceptions: []armotypes.PostureExceptionPolicy{
				auditSourceException(overlapping, nil, "C-0001", "C-0002"),
				auditSourceException(overlapping, nil, "C-0001", "C-0003"),
			},
			want: map[string]string{"C-0001,C-0002": "matched/2", "C-0001,C-0003": "matched/2"},
		},
		{
			name: "copies narrowed to a shared control",
			exceptions: []armotypes.PostureExceptionPolicy{
				auditSourceException(nginx, nil, "C-0001", "C-0002"),
				auditSourceException(nginx, nil, "C-0001", "C-0003"),
			},
			want: map[string]string{"C-0001,C-0002": "matched/1", "C-0001,C-0003": "matched/1"},
		},
		{
			// The first exception's narrowed copy has exactly the content of the
			// second one; only its source index tells them apart.
			name: "narrowed copy identical to another exception",
			exceptions: []armotypes.PostureExceptionPolicy{
				auditSourceException(nginx, nil, "C-0001", "C-0002"),
				auditSourceException(nginx, nil, "C-0001"),
			},
			want: map[string]string{"C-0001,C-0002": "matched/1", "C-0001": "matched/1"},
		},
		{
			name: "scope-less exceptions",
			exceptions: []armotypes.PostureExceptionPolicy{
				auditSourceException(nil, nil, "C-0001", "C-0002"),
				auditSourceException(nil, nil, "C-0001", "C-0003"),
			},
			want: map[string]string{"C-0001,C-0002": "matched/1", "C-0001,C-0003": "matched/1"},
		},
		{
			name: "unused exception",
			exceptions: []armotypes.PostureExceptionPolicy{
				auditSourceException(nginx, nil, "C-0001"),
				auditSourceException(oldApp, nil, "C-0017"),
			},
			want: map[string]string{"C-0001": "matched/1", "C-0017": "unused/0"},
		},
		{
			name: "expired exception",
			exceptions: []armotypes.PostureExceptionPolicy{
				auditSourceException(nginx, nil, "C-0001"),
				auditSourceException(oldApp, &expiredAt, "C-0017"),
			},
			want: map[string]string{"C-0001": "matched/1", "C-0017": "expired/0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			distinct := make([]armotypes.PostureExceptionPolicy, len(tc.exceptions))
			for i, exception := range tc.exceptions {
				distinct[i] = exception
				distinct[i].Name = fmt.Sprintf("exception-%d", i)
			}

			sameName := auditItemsByControls(runUpdateResultsAudit(t, tc.exceptions))
			assert.Equal(t, tc.want, sameName)
			assert.Equal(t, auditItemsByControls(runUpdateResultsAudit(t, distinct)), sameName,
				"same-named exceptions must be audited exactly like distinctly named ones")
		})
	}
}

// Identical repeats of one exception share an item that collects the matches of
// every occurrence, and never take matches from a different same-named exception.
func TestUpdateResults_ExceptionAuditGroupsIdenticalRepeats(t *testing.T) {
	nginx := []identifiers.PortalDesignator{auditDesignator("kind", "Deployment", "namespace", "default", "name", "nginx")}
	overlapping := []identifiers.PortalDesignator{auditDesignator("kind", "Deployment"), auditDesignator("namespace", "default")}

	for _, tc := range []struct {
		name      string
		resources []identifiers.PortalDesignator
		want      map[string]string
	}{
		{name: "single selector", resources: nginx, want: map[string]string{"C-0001,C-0002": "matched/1", "C-0001,C-0003": "matched/2"}},
		{name: "overlapping resource selectors", resources: overlapping, want: map[string]string{"C-0001,C-0002": "matched/2", "C-0001,C-0003": "matched/4"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repeated := auditSourceException(tc.resources, nil, "C-0001", "C-0003")
			audit := runUpdateResultsAudit(t, []armotypes.PostureExceptionPolicy{
				auditSourceException(tc.resources, nil, "C-0001", "C-0002"),
				repeated,
				repeated,
			})
			assert.Equal(t, tc.want, auditItemsByControls(audit))
			assert.Equal(t, 2, audit.Summary.Total)
			assert.Equal(t, 2, audit.Summary.Active)
		})
	}
}

// runUpdateResultsAudit runs updateResults with the audit enabled over a
// Deployment default/nginx that fails C-0001 through rule-a. It also checks that
// the source index used by the audit leaves no trace: the input policies are not
// modified and the results are the same as with the audit disabled.
func runUpdateResultsAudit(t *testing.T, loaded []armotypes.PostureExceptionPolicy) *cautils.ExceptionAudit {
	t.Helper()
	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "nginx", "namespace": "default"},
	})
	run := func(audit bool) *OPAProcessor {
		session := cautils.NewOPASessionObjMock()
		session.AuditExceptions = audit
		session.AllResources[resource.GetID()] = resource
		session.ResourcesResult[resource.GetID()] = resourcesresults.Result{
			ResourceID: resource.GetID(),
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID:               "C-0001",
				Name:                    "control-1",
				Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "rule-a", Status: apis.StatusFailed}},
			}},
		}
		session.Exceptions = loaded
		session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{
			"C-0001": {ControlID: "C-0001"},
			"C-0002": {ControlID: "C-0002"},
			"C-0003": {ControlID: "C-0003"},
			"C-0017": {ControlID: "C-0017"},
		}}
		session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0001": {ControlID: "C-0001"}}
		opap := &OPAProcessor{OPASessionObj: session}
		opap.updateResults(context.Background())
		return opap
	}

	before, err := json.Marshal(loaded)
	require.NoError(t, err)
	audited, plain := run(true), run(false)
	after, err := json.Marshal(loaded)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after), "input policies must remain intact")

	auditedResults, err := json.Marshal(audited.ResourcesResult)
	require.NoError(t, err)
	plainResults, err := json.Marshal(plain.ResourcesResult)
	require.NoError(t, err)
	assert.JSONEq(t, string(plainResults), string(auditedResults), "the audit must not change scan results")
	assert.NotContains(t, string(auditedResults), exceptionAuditSourceAttribute)
	for _, exception := range audited.Exceptions {
		assert.NotContains(t, exception.Attributes, exceptionAuditSourceAttribute)
	}

	require.NotNil(t, audited.ExceptionAudit)
	return audited.ExceptionAudit
}

func auditItemsByControls(audit *cautils.ExceptionAudit) map[string]string {
	items := make(map[string]string, len(audit.Items))
	for _, item := range audit.Items {
		items[strings.Join(item.ControlIDs, ",")] = fmt.Sprintf("%s/%d", item.Status, item.MatchCount)
	}
	return items
}

func auditSourceException(resources []identifiers.PortalDesignator, expirationDate *time.Time, controlIDs ...string) armotypes.PostureExceptionPolicy {
	exception := armotypes.PostureExceptionPolicy{
		PortalBase:     armotypes.PortalBase{Name: "shared"},
		PolicyType:     "postureExceptionPolicy",
		Actions:        []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
		Resources:      resources,
		ExpirationDate: expirationDate,
	}
	for _, controlID := range controlIDs {
		exception.PosturePolicies = append(exception.PosturePolicies, armotypes.PosturePolicy{ControlID: controlID})
	}
	return exception
}

func auditDesignator(keyValues ...string) identifiers.PortalDesignator {
	attributes := make(map[string]string, len(keyValues)/2)
	for i := 0; i+1 < len(keyValues); i += 2 {
		attributes[keyValues[i]] = keyValues[i+1]
	}
	return identifiers.PortalDesignator{DesignatorType: identifiers.DesignatorAttributes, Attributes: attributes}
}

// Two distinct same-named exceptions matching one manual control each keep their
// match, and an exception applied through several frameworks counts once.
func TestUpdateResults_ExceptionAuditKeepsSameNameManualMatchesApart(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.AuditExceptions = true
	manual := reportsummary.ControlSummary{ControlID: "C-0286", StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview}}
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0286": manual}
	for _, name := range []string{"NSA", "MITRE"} {
		session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: name, Controls: reportsummary.ControlSummaries{"C-0286": manual}})
	}
	session.Exceptions = []armotypes.PostureExceptionPolicy{
		{PortalBase: armotypes.PortalBase{Name: "shared"}, PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}, {FrameworkName: "MITRE", ControlID: "C-0286"}}},
		{PortalBase: armotypes.PortalBase{Name: "shared"}, PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}, {ControlID: "C-0001"}}},
	}

	opap := &OPAProcessor{OPASessionObj: session}
	opap.updateResults(context.Background())

	audit := opap.ExceptionAudit
	require.NotNil(t, audit)
	require.Len(t, audit.Items, 2)
	assert.Equal(t, 2, audit.Summary.Matched)
	for _, item := range audit.Items {
		assert.Equal(t, 1, item.MatchCount, "item %v", item.ControlIDs)
	}
}

// Policies sharing a GUID are one exception, so a manual control they both
// match is counted once.
func TestUpdateResults_ExceptionAuditCountsSameGUIDManualMatchOnce(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.AuditExceptions = true
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		"C-0286": {ControlID: "C-0286", StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview}},
	}
	first := auditExceptionWithGUID("g", "cloud", "C-0286", nil)
	second := auditExceptionWithGUID("g", "cloud", "C-0286", nil)
	second.PosturePolicies = append(second.PosturePolicies, armotypes.PosturePolicy{ControlID: "C-0001"})
	session.Exceptions = []armotypes.PostureExceptionPolicy{first, second}

	opap := &OPAProcessor{OPASessionObj: session}
	opap.updateResults(context.Background())

	require.Len(t, opap.ExceptionAudit.Items, 1)
	assert.Equal(t, 1, opap.ExceptionAudit.Items[0].MatchCount)
}

func auditException(name, controlID string, expirationDate *time.Time) armotypes.PostureExceptionPolicy {
	return auditExceptionWithGUID("", name, controlID, expirationDate)
}

func auditExceptionWithGUID(guid, name, controlID string, expirationDate *time.Time) armotypes.PostureExceptionPolicy {
	return armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{GUID: guid, Name: name},
		PosturePolicies: []armotypes.PosturePolicy{
			{ControlID: controlID},
		},
		ExpirationDate: expirationDate,
	}
}
