package podsec

import (
    "context"
    "fmt"
    "kube-sec-audit/pkg/reporter"

    v1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
)

func AnalyzePodSecurity(clientset *kubernetes.Clientset, report *reporter.Report) error {
    pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return err
    }

    for _, pod := range pods.Items {
        for _, container := range pod.Spec.Containers {
            sc := container.SecurityContext
            if sc == nil {
                report.AddFinding(reporter.Finding{
                    Module:    "podsec",
                    Namespace: pod.Namespace,
                    Resource:  pod.Name,
                    RiskLevel: "medium",
                    Message:   fmt.Sprintf("Container '%s' has no securityContext defined", container.Name),
                })
                continue
            }

            if sc.Privileged != nil && *sc.Privileged {
                report.AddFinding(reporter.Finding{
                    Module:    "podsec",
                    Namespace: pod.Namespace,
                    Resource:  pod.Name,
                    RiskLevel: "critical",
                    Message:   fmt.Sprintf("Container '%s' is running in privileged mode", container.Name),
                })
            }

            if sc.RunAsNonRoot != nil && !*sc.RunAsNonRoot {
                report.AddFinding(reporter.Finding{
                    Module:    "podsec",
                    Namespace: pod.Namespace,
                    Resource:  pod.Name,
                    RiskLevel: "high",
                    Message:   fmt.Sprintf("Container '%s' allows root user", container.Name),
                })
            }

            if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
                report.AddFinding(reporter.Finding{
                    Module:    "podsec",
                    Namespace: pod.Namespace,
                    Resource:  pod.Name,
                    RiskLevel: "high",
                    Message:   fmt.Sprintf("Privilege escalation allowed in container '%s'", container.Name),
                })
            }

            if sc.ReadOnlyRootFilesystem != nil && !*sc.ReadOnlyRootFilesystem {
                report.AddFinding(reporter.Finding{
                    Module:    "podsec",
                    Namespace: pod.Namespace,
                    Resource:  pod.Name,
                    RiskLevel: "medium",
                    Message:   fmt.Sprintf("Root filesystem is not read-only in container '%s'", container.Name),
                })
            }

            if sc.Capabilities != nil && len(sc.Capabilities.Add) > 0 {
                report.AddFinding(reporter.Finding{
                    Module:    "podsec",
                    Namespace: pod.Namespace,
                    Resource:  pod.Name,
                    RiskLevel: "high",
                    Message:   fmt.Sprintf("Extra Linux capabilities added in container '%s': %v", container.Name, sc.Capabilities.Add),
                })
            }
        }
    }

    return nil
}
