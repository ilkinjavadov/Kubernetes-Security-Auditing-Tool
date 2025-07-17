package rbac

import (
    "context"
    "fmt"
    "kube-sec-audit/pkg/reporter"
    rbacv1 "k8s.io/api/rbac/v1"
    "k8s.io/client-go/kubernetes"
)

var dangerousVerbs = []string{"create", "delete", "update", "patch", "*"}

func AnalyzeRBAC(clientset *kubernetes.Clientset, report *reporter.Report) error {
    ctx := context.TODO()

    roles, _ := clientset.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
    clusterRoles, _ := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})

    for _, role := range roles.Items {
        analyzeRules("Role", role.Namespace, role.Name, role.Rules, report)
    }

    for _, crole := range clusterRoles.Items {
        analyzeRules("ClusterRole", "", crole.Name, crole.Rules, report)
    }

    return nil
}

func analyzeRules(kind, ns, name string, rules []rbacv1.PolicyRule, report *reporter.Report) {
    for _, rule := range rules {
        for _, verb := range rule.Verbs {
            if isDangerous(verb) {
                report.AddFinding(reporter.Finding{
                    Module:    "rbac",
                    Namespace: ns,
                    Resource:  fmt.Sprintf("%s/%s", kind, name),
                    RiskLevel: "high",
                    Message:   fmt.Sprintf("Dangerous verb '%s' used in resource(s): %v", verb, rule.Resources),
                })
            }
        }
        if contains(rule.Verbs, "*") {
            report.AddFinding(reporter.Finding{
                Module:    "rbac",
                Namespace: ns,
                Resource:  fmt.Sprintf("%s/%s", kind, name),
                RiskLevel: "critical",
                Message:   "Wildcard verb '*' detected – full access granted",
            })
        }
    }
}

func isDangerous(verb string) bool {
    for _, dv := range dangerousVerbs {
        if verb == dv {
            return true
        }
    }
    return false
}

func contains(slice []string, val string) bool {
    for _, item := range slice {
        if item == val {
            return true
        }
    }
    return false
}
