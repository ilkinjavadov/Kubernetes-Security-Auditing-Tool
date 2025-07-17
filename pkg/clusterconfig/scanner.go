package clusterconfig

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

func (s *Scanner) ScanClusterRoleBindings() error {
    bindings, err := s.Clientset.RbacV1().ClusterRoleBindings().List(context.Background(), metav1.ListOptions{})
    if err != nil {
        return err
    }
    fmt.Println("ClusterRoleBindings:")
    for _, b := range bindings.Items {
        fmt.Printf("Name: %s\n", b.Name)
        fmt.Printf("RoleRef: %s\n", b.RoleRef.Name)
        fmt.Printf("Subjects:\n")
        for _, subject := range b.Subjects {
            fmt.Printf("  - Kind: %s, Name: %s, Namespace: %s\n", subject.Kind, subject.Name, subject.Namespace)
        }
        fmt.Println("-------------------------")
    }
    return nil
}
