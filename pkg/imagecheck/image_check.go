package imagecheck

import (
    "context"
    "fmt"
    "strings"
    "kube-sec-audit/pkg/reporter"

    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
)

func AnalyzeImages(clientset *kubernetes.Clientset, report *reporter.Report) error {
    pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return err
    }

    for _, pod := range pods.Items {
        for _, container := range pod.Spec.Containers {
            image := container.Image

            if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
                report.AddFinding(reporter.Finding{
                    Module:    "imagecheck",
                    Namespace: pod.Namespace,
                    Resource:  pod.Name,
                    RiskLevel: "medium",
                    Message:   fmt.Sprintf("Container '%s' uses 'latest' or no tag in image: %s", container.Name, image),
                })
            }

            // Burada ileri seviye: CVE veritabanı vs. ile entegrasyon eklenebilir
        }
    }

    return nil
}
