package secretdetector

import (
    "context"
    "encoding/base64"
    "fmt"
    "regexp"

    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
)

type Detector struct {
    Clientset *kubernetes.Clientset
}

func NewDetector(kubeconfig string) (*Detector, error) {
    config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
    if err != nil {
        return nil, err
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, err
    }

    return &Detector{Clientset: clientset}, nil
}

func (d *Detector) ScanSecrets() error {
    fmt.Println("🔍 Scanning Secrets and ConfigMaps for sensitive data...")

    namespaces, err := d.Clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
    if err != nil {
        return err
    }

    patterns := []*regexp.Regexp{
        regexp.MustCompile(`(?i)(aws|gcp|azure)?_?(access|secret)?_?key[^=]*[:=]\s*["']?([A-Za-z0-9/\+=]{20,})["']?`),
        regexp.MustCompile(`(?i)(token|password|pass|secret)[^=]*[:=]\s*["']?([A-Za-z0-9/\+=@#$%^&*()!~]{6,})["']?`),
        regexp.MustCompile(`(?i)BEGIN RSA PRIVATE KEY`),
    }

    for _, ns := range namespaces.Items {
        // 🔐 Scan Secrets
        secrets, _ := d.Clientset.CoreV1().Secrets(ns.Name).List(context.Background(), metav1.ListOptions{})
        for _, s := range secrets.Items {
            for k, v := range s.Data {
                decoded := string(v)
                for _, pat := range patterns {
                    if pat.MatchString(decoded) {
                        fmt.Printf("⚠️ Suspicious secret in [%s/%s] key=%s\n", ns.Name, s.Name, k)
                        break
                    }
                }
            }
        }

        // 🧾 Scan ConfigMaps
        configMaps, _ := d.Clientset.CoreV1().ConfigMaps(ns.Name).List(context.Background(), metav1.ListOptions{})
        for _, cm := range configMaps.Items {
            for k, v := range cm.Data {
                for _, pat := range patterns {
                    if pat.MatchString(v) {
                        fmt.Printf("⚠️ Suspicious config in [%s/%s] key=%s\n", ns.Name, cm.Name, k)
                        break
                    }
                }
            }
        }
    }

    return nil
}
