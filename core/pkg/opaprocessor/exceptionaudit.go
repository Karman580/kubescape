package opaprocessor

import (
	"maps"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	exceptionAuditStatusExpired        = "expired"
	exceptionAuditStatusInvalidControl = "invalid-control"
	exceptionAuditStatusMatched        = "matched"
	exceptionAuditStatusUnused         = "unused"
)

// exceptionAuditSourceAttribute records a loaded exception's index while
// updateResults applies exceptions, so every copy the exceptions processor
// attaches to a rule result can be traced to its source. Content cannot do
// this: copies are narrowed to the matching posture policies, scope-less ones
// get a resource designator, and getResourceExceptions repeats a copy once per
// matching designator.
const exceptionAuditSourceAttribute = "kubescape.io/exception-audit-source"

// tagExceptionAuditSources returns a copy of exceptionPolicies with each
// policy's index recorded under exceptionAuditSourceAttribute. Attribute maps
// are cloned, so caller-owned policies are left intact.
func tagExceptionAuditSources(exceptionPolicies []armotypes.PostureExceptionPolicy) []armotypes.PostureExceptionPolicy {
	tagged := slices.Clone(exceptionPolicies)
	for i := range tagged {
		attributes := maps.Clone(tagged[i].Attributes)
		if attributes == nil {
			attributes = make(map[string]any, 1)
		}
		attributes[exceptionAuditSourceAttribute] = i
		tagged[i].Attributes = attributes
	}
	return tagged
}

// untagExceptionAuditSource gives a tagged policy back the attributes of its
// source in originals.
func untagExceptionAuditSource(exception *armotypes.PostureExceptionPolicy, originals []armotypes.PostureExceptionPolicy) {
	if i, ok := exceptionAuditSource(*exception); ok && i < len(originals) {
		exception.Attributes = originals[i].Attributes
	}
}

func exceptionAuditSource(exception armotypes.PostureExceptionPolicy) (int, bool) {
	i, ok := exception.Attributes[exceptionAuditSourceAttribute].(int)
	return i, ok && i >= 0
}

func buildExceptionAudit(
	loadedExceptions []armotypes.PostureExceptionPolicy,
	activeExceptions []armotypes.PostureExceptionPolicy,
	results map[string]resourcesresults.Result,
	catalog cautils.ResourceCatalog,
	policies *cautils.Policies,
	processor *exceptions.Processor,
	manualControlMatches []manualControlExceptionMatch,
	summary *reportsummary.SummaryDetails,
) *cautils.ExceptionAudit {
	items := make(map[string]*cautils.ExceptionAuditItem, len(loadedExceptions))
	active := make(map[string]struct{}, len(activeExceptions))
	// sourceItems maps each loaded exception, by index, to its audit item. Exceptions
	// with a GUID share an item per GUID. Exceptions without one (local files,
	// SecurityException CRDs) are keyed by name, which is not unique, so each distinct
	// one gets its own item; identical repeats share one.
	sourceItems := make([]string, len(loadedExceptions))
	distinct := make(map[string]int, len(loadedExceptions))
	for i, exception := range loadedExceptions {
		key := exceptionAuditKey(exception)
		id := ""
		for j := range i {
			if exceptionAuditKey(loadedExceptions[j]) == key && (exception.GUID != "" || identicalExceptions(loadedExceptions[j], exception)) {
				id = sourceItems[j]
				break
			}
		}
		if id == "" {
			id = key
			if n := distinct[key]; n > 0 {
				// "\x00" sorts first, keeping same-named items together.
				id = key + "\x00" + strconv.Itoa(n)
			}
			distinct[key]++
			item := exceptionAuditItem(exception, policies, processor)
			items[id] = &item
		}
		sourceItems[i] = id
	}

	// resolve returns the item of the loaded exception that exception came from.
	// Exceptions without a source index (callers that did not tag them) fall back to
	// the GUID-or-name key.
	resolve := func(exception armotypes.PostureExceptionPolicy) string {
		if i, ok := exceptionAuditSource(exception); ok && i < len(sourceItems) {
			return sourceItems[i]
		}
		key := exceptionAuditKey(exception)
		if _, ok := items[key]; !ok {
			item := exceptionAuditItem(exception, policies, processor)
			items[key] = &item
		}
		return key
	}

	for _, exception := range activeExceptions {
		active[resolve(exception)] = struct{}{}
	}

	for resourceID, result := range results {
		var resource workloadinterface.IMetadata
		if catalog != nil {
			resource, _ = catalog.Get(resourceID)
		}
		for _, control := range result.AssociatedControls {
			controlID := control.GetID()
			for _, rule := range control.ResourceAssociatedRules {
				for _, exception := range rule.Exception {
					// Match with framework context, but retain the original policy's
					// identity and tuples in the audit entry.
					if len(exceptions.FilterExceptionsByFrameworks([]armotypes.PostureExceptionPolicy{exception}, cautils.ControlFilters(summary, controlID).FrameworkNames, controlID, rule.GetName())) == 0 {
						continue
					}
					key := resolve(exception)
					items[key].MatchCount++
					items[key].MatchedResources = append(items[key].MatchedResources, exceptionAuditMatch(resourceID, controlID, rule.GetName(), resource))
				}
			}
		}
	}

	// Manual controls never appear in results (they have no resourcesresults.Result
	// entries at all), so without this an exception that only suppresses a manual
	// control is reported as unused even though it is actively applied.
	// A partial framework match is still an audit match, but an exception counts
	// once per manual control, however many frameworks, identical repeats or
	// policies sharing its GUID matched it.
	counted := make(map[[2]string]struct{}, len(manualControlMatches))
	for _, match := range manualControlMatches {
		key := resolve(match.exception)
		if _, ok := counted[[2]string{key, match.controlID}]; ok {
			continue
		}
		counted[[2]string{key, match.controlID}] = struct{}{}
		items[key].MatchCount++
		items[key].MatchedResources = append(items[key].MatchedResources, cautils.ExceptionAuditMatch{ControlID: match.controlID})
	}

	audit := &cautils.ExceptionAudit{
		Generated: true,
		Items:     make([]cautils.ExceptionAuditItem, 0, len(items)),
	}

	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	audit.Summary.Total = len(keys)
	for _, key := range keys {
		item := items[key]
		if _, ok := active[key]; ok {
			audit.Summary.Active++
		}
		if item.Expired {
			item.Status = exceptionAuditStatusExpired
			audit.Summary.Expired++
		} else if len(item.InvalidControls) > 0 {
			item.Status = exceptionAuditStatusInvalidControl
			audit.Summary.InvalidControl++
		} else if item.MatchCount > 0 {
			item.Status = exceptionAuditStatusMatched
			audit.Summary.Matched++
		} else {
			item.Status = exceptionAuditStatusUnused
			audit.Summary.Unused++
		}
		sort.Strings(item.ControlIDs)
		sort.Strings(item.InvalidControls)
		sort.Slice(item.MatchedResources, func(i, j int) bool {
			if item.MatchedResources[i].ResourceID == item.MatchedResources[j].ResourceID {
				if item.MatchedResources[i].ControlID == item.MatchedResources[j].ControlID {
					return item.MatchedResources[i].RuleName < item.MatchedResources[j].RuleName
				}
				return item.MatchedResources[i].ControlID < item.MatchedResources[j].ControlID
			}
			return item.MatchedResources[i].ResourceID < item.MatchedResources[j].ResourceID
		})
		audit.Items = append(audit.Items, *item)
	}

	return audit
}

func exceptionAuditItem(exception armotypes.PostureExceptionPolicy, policies *cautils.Policies, processor *exceptions.Processor) cautils.ExceptionAuditItem {
	item := cautils.ExceptionAuditItem{
		Name:       exceptionAuditName(exception),
		Expired:    exceptionIsExpired(exception),
		ControlIDs: exceptionControlIDs(exception),
	}
	item.InvalidControls = invalidExceptionControls(item.ControlIDs, policies, processor)
	return item
}

func exceptionAuditKey(exception armotypes.PostureExceptionPolicy) string {
	if exception.GUID != "" {
		return exception.GUID
	}
	return exceptionAuditName(exception)
}

// identicalExceptions reports whether a and b are the same policy, ignoring the
// source index recorded by tagExceptionAuditSources.
func identicalExceptions(a, b armotypes.PostureExceptionPolicy) bool {
	a.Attributes, b.Attributes = withoutExceptionAuditSource(a.Attributes), withoutExceptionAuditSource(b.Attributes)
	return reflect.DeepEqual(a, b)
}

func withoutExceptionAuditSource(attributes map[string]any) map[string]any {
	if _, ok := attributes[exceptionAuditSourceAttribute]; !ok {
		return attributes
	}
	attributes = maps.Clone(attributes)
	delete(attributes, exceptionAuditSourceAttribute)
	if len(attributes) == 0 {
		return nil
	}
	return attributes
}

func exceptionAuditName(exception armotypes.PostureExceptionPolicy) string {
	if exception.Name != "" {
		return exception.Name
	}
	return exception.GetName()
}

func exceptionIsExpired(exception armotypes.PostureExceptionPolicy) bool {
	return exception.ExpirationDate != nil && !exception.ExpirationDate.After(time.Now())
}

func exceptionControlIDs(exception armotypes.PostureExceptionPolicy) []string {
	seen := map[string]struct{}{}
	var controlIDs []string
	for _, posturePolicy := range exception.PosturePolicies {
		if posturePolicy.ControlID == "" {
			continue
		}
		if _, ok := seen[posturePolicy.ControlID]; ok {
			continue
		}
		seen[posturePolicy.ControlID] = struct{}{}
		controlIDs = append(controlIDs, posturePolicy.ControlID)
	}
	return controlIDs
}

func invalidExceptionControls(controlIDs []string, policies *cautils.Policies, processor *exceptions.Processor) []string {
	if len(controlIDs) == 0 || policies == nil || len(policies.Controls) == 0 {
		return nil
	}
	if processor == nil {
		processor = exceptions.NewProcessor()
	}

	var invalid []string
	for _, controlID := range controlIDs {
		found := false
		for existingID := range policies.Controls {
			if processor.RegexCompareControlID(controlID, existingID) {
				found = true
				break
			}
		}
		if !found {
			invalid = append(invalid, controlID)
		}
	}
	return invalid
}

func exceptionAuditMatch(resourceID, controlID, ruleName string, resource workloadinterface.IMetadata) cautils.ExceptionAuditMatch {
	match := cautils.ExceptionAuditMatch{
		ResourceID: resourceID,
		ControlID:  controlID,
		RuleName:   ruleName,
	}
	if resource == nil {
		return match
	}
	match.Kind = resource.GetKind()
	match.Namespace = resource.GetNamespace()
	match.Name = resource.GetName()
	return match
}
