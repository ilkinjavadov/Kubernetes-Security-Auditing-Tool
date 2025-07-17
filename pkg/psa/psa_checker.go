package psa

import (
    "context"
    "fmt"
    "kube-sec-audit/pkg/reporter"

    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
)

func CheckPSACompliance(clientset *kubernetes.Clientset, report *reporter.Report) error {
    pods, _ := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})

    for _, pod := range pods.Items {
        namespace := pod.Namespace
        name := pod.Name

        if pod.Spec.SecurityContext == nil {
            report.AddFinding(reporter.Finding{
                Module:    "psa",
                Resource:  fmt.Sprintf("%s/%s", namespace, name),
                RiskLevel: "high",
                Message:   "Missing pod-level securityContext (non-compliant with Restricted PSA)",
            })
        }

        for _, c := range pod.Spec.Containers {
            sc := c.SecurityContext
            if sc == nil {
                report.AddFinding(reporter.Finding{
                    Module:    "psa",
                    Resource:  fmt.Sprintf("%s/%s", namespace, name),
                    RiskLevel: "high",
                    Message:   fmt.Sprintf("Container '%s' has no securityContext", c.Name),
                })
                continue
            }

            if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
                report.AddFinding(reporter.Finding{
                    Module:    "psa",
                    Resource:  fmt.Sprintf("%s/%s", namespace, name),
                    RiskLevel: "high",
                    Message:   fmt.Sprintf("Container '%s' allows privilege escalation", c.Name),
                })
            }

            if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
                report.AddFinding(reporter.Finding{
                    Module:    "psa",
                    Resource:  fmt.Sprintf("%s/%s", namespace, name),
                    RiskLevel: "medium",
                    Message:   fmt.Sprintf("Container '%s' does not enforce runAsNonRoot", c.Name),
                })
            }

            if sc.SeccompProfile == nil || sc.SeccompProfile.Type == "" {
                report.AddFinding(reporter.Finding{
                    Module:    "psa",
                    Resource:  fmt.Sprintf("%s/%s", namespace, name),
                    RiskLevel: "medium",
                    Message:   fmt.Sprintf("Container '%s' lacks seccomp profile (should use RuntimeDefault)", c.Name),
                })
            }
        }
    }

    return nil
}
