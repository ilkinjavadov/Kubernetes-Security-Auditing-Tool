package podsecurity

import (
    "context"
    "fmt"

    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
)

type Scanner struct {
    Clientset *kubernetes.Clientset
}

func NewScanner(kubeconfigPath string) (*Scanner, error) {
    config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
    if err != nil {
        return nil, err
    }
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, err
    }
    return &Scanner{Clientset: clientset}, nil
}

func (s *Scanner) ScanPodsSecurity() error {
    pods, err := s.Clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
    if err != nil {
        return err
    }

    fmt.Println("Pod Security Analysis:")
    for _, pod := range pods.Items {
        for _, container := range pod.Spec.Containers {
            issues := []string{}

            if container.SecurityContext == nil {
                issues = append(issues, "Missing SecurityContext")
            } else {
                if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
                    issues = append(issues, "Running as root")
                }
                if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
                    issues = append(issues, "Privileged container")
                }
                if container.SecurityContext.Capabilities != nil &&
                    len(container.SecurityContext.Capabilities.Add) > 0 {
                    issues = append(issues, "Extra Linux capabilities added")
                }
            }

            if pod.Spec.HostNetwork {
                issues = append(issues, "HostNetwork enabled")
            }
            if pod.Spec.HostPID {
                issues = append(issues, "HostPID enabled")
            }
            if pod.Spec.HostIPC {
                issues = append(issues, "HostIPC enabled")
            }

            if len(issues) > 0 {
                fmt.Printf("⚠️  Namespace: %s, Pod: %s, Container: %s\n", pod.Namespace, pod.Name, container.Name)
                for _, issue := range issues {
                    fmt.Printf("   - %s\n", issue)
                }
                fmt.Println("------------------------")
            }
        }
    }
    return nil
}
