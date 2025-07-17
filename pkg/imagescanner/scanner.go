package imagescanner

import (
    "context"
    "fmt"
    "os/exec"
    "strings"

    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
)

type Scanner struct {
    Clientset *kubernetes.Clientset
}

func NewScanner(kubeconfig string) (*Scanner, error) {
    config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
    if err != nil {
        return nil, err
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, err
    }

    return &Scanner{Clientset: clientset}, nil
}

func (s *Scanner) ScanImages() error {
    pods, err := s.Clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
    if err != nil {
        return err
    }

    uniqueImages := make(map[string]bool)

    fmt.Println("🔍 Scanning container images with Trivy:")

    for _, pod := range pods.Items {
        for _, container := range pod.Spec.Containers {
            image := container.Image
            if _, scanned := uniqueImages[image]; scanned {
                continue
            }
            uniqueImages[image] = true

            fmt.Printf("\n🖼️ Image: %s\n", image)
            cmd := exec.Command("trivy", "-q", "image", "--severity", "CRITICAL,HIGH", image)
            output, err := cmd.CombinedOutput()
            if err != nil && !strings.Contains(string(output), "CRITICAL") && !strings.Contains(string(output), "HIGH") {
                fmt.Printf("   ⚠️ Trivy scan error: %v\n", err)
            }

            fmt.Println(string(output))
        }
    }

    return nil
}
