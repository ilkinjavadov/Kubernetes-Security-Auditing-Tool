package rbac

import (
    "context"
    "fmt"
    "strings"

    "kube-sec-audit/pkg/reporter"

    rbacv1 "k8s.io/api/rbac/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
)

func AnalyzeRBAC(clientset *kubernetes.Clientset, report *reporter.Report) error {
    // ClusterRoles
    clusterRoles, _ := clientset.RbacV1().ClusterRoles().List(context.TODO(), metav1.ListOptions{})
    for _, cr := range clusterRoles.Items {
        for _, rule := range cr.Rules {
            if isFullAccess(rule) {
                report.AddFinding(reporter.Finding{
                    Module:   "rbac",
                    Resource: cr.Name,
                    RiskLevel: "critical",
                    Message:  "ClusterRole grants full access to all resources with '*'",
                })
            }
        }
    }

    // ClusterRoleBindings
    crbs, _ := clientset.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
    for _, crb := range crbs.Items {
        if strings.Contains(strings.ToLower(crb.RoleRef.Name), "admin") || strings.Contains(strings.ToLower(crb.RoleRef.Name), "cluster-admin") {
            for _, subject := range crb.Subjects {
                report.AddFinding(reporter.Finding{
                    Module:   "rbac",
                    Resource: fmt.Sprintf("%s -> %s", subject.Name, crb.RoleRef.Name),
                    RiskLevel: "high",
                    Message:  "Subject is bound to an admin-level ClusterRole",
                })
            }
        }
    }

    return nil
}

func isFullAccess(rule rbacv1.PolicyRule) bool {
    return contains(rule.APIGroups, "*") && contains(rule.Resources, "*") && contains(rule.Verbs, "*")
}

func contains(slice []string, s string) bool {
    for _, item := range slice {
        if item == s {
            return true
        }
    }
    return false
}
