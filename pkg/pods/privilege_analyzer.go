package pods

import (
    "context"
    "fmt"
    "kube-sec-audit/pkg/reporter"

    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
)

func AnalyzePrivilegedPods(clientset *kubernetes.Clientset, report *reporter.Report) error {
    pods, _ := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
    for _, pod := range pods.Items {
        for _, c := range pod.Spec.Containers {
            sc := c.SecurityContext
            if sc != nil {
                if sc.Privileged != nil && *sc.Privileged {
                    report.AddFinding(reporter.Finding{
                        Module:   "privilege",
                        Resource: fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
                        RiskLevel: "high",
                        Message:  "Container is running in privileged mode",
                    })
                }

                if sc.Capabilities != nil {
                    for _, cap := range sc.Capabilities.Add {
                        if isRiskyCapability(cap) {
                            report.AddFinding(reporter.Finding{
                                Module:   "privilege",
                                Resource: fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
                                RiskLevel: "medium",
                                Message:  fmt.Sprintf("Container adds risky capability: %s", cap),
                            })
                        }
                    }
                }
            }
        }

        if pod.Spec.HostNetwork {
            report.AddFinding(reporter.Finding{
                Module:   "privilege",
                Resource: fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
                RiskLevel: "medium",
                Message:  "Pod uses hostNetwork",
            })
        }

        if pod.Spec.HostPID {
            report.AddFinding(reporter.Finding{
                Module:   "privilege",
                Resource: fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
                RiskLevel: "medium",
                Message:  "Pod uses hostPID",
            })
        }

        if pod.Spec.HostIPC {
            report.AddFinding(reporter.Finding{
                Module:   "privilege",
                Resource: fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
                RiskLevel: "medium",
                Message:  "Pod uses hostIPC",
            })
        }

        for _, vol := range pod.Spec.Volumes {
            if vol.HostPath != nil {
                report.AddFinding(reporter.Finding{
                    Module:   "privilege",
                    Resource: fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
                    RiskLevel: "high",
                    Message:  fmt.Sprintf("Pod mounts hostPath: %s", vol.HostPath.Path),
                })
            }
        }
    }

    return nil
}

func isRiskyCapability(cap corev1.Capability) bool {
    risky := []string{
        "NET_ADMIN", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "KILL", "AUDIT_CONTROL",
    }
    for _, r := range risky {
        if string(cap) == r {
            return true
        }
    }
    return false
}
