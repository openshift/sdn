package proxy

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilwait "k8s.io/apimachinery/pkg/util/wait"

	unidlingapi "github.com/openshift/api/unidling/v1alpha1"
)

func makeService(namespace, name string) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			UID:         ktypes.UID(namespace + "/" + name),
			Annotations: make(map[string]string),
		},
	}

	return svc
}

func createServiceAndWait(svc *corev1.Service, proxy *OsdnProxy) error {
	_, err := proxy.kClient.CoreV1().Services(svc.Namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	serviceLister := proxy.kubeInformers.Core().V1().Services().Lister()
	return utilwait.Poll(10*time.Millisecond, time.Second, func() (bool, error) {
		_, err := serviceLister.Services(svc.Namespace).Get(svc.Name)
		if err != nil {
			return false, nil
		}
		return true, nil
	})
}

func deleteServiceAndWait(svc *corev1.Service, proxy *OsdnProxy) error {
	err := proxy.kClient.CoreV1().Services(svc.Namespace).Delete(context.TODO(), svc.Name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	serviceLister := proxy.kubeInformers.Core().V1().Services().Lister()
	return utilwait.Poll(10*time.Millisecond, time.Second, func() (bool, error) {
		_, err := serviceLister.Services(svc.Namespace).Get(svc.Name)
		if err == nil {
			return false, nil
		}
		return true, nil
	})
}

func TestHybridProxy(t *testing.T) {
	proxy, mainProxy, unidlingProxy, err := newTestOsdnProxy()
	if err != nil {
		t.Fatalf("unexpected error creating OsdnProxy: %v", err)
	}

	// *****

	// Create a Service...
	svc1 := makeService("testns", "one")
	err = createServiceAndWait(svc1, proxy)
	if err != nil {
		t.Fatalf("unexpected error creating service: %v", err)
	}
	proxy.OnServiceAdd(svc1)

	err = mainProxy.assertEvents("after creating first service",
		"add service testns/one",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after creating first service")
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Then create its endpoints. Note that the unidling proxy is told about all
	// endpoints changes, even though it doesn't know about the service
	ep1 := makeEndpoints("testns", "one", "1.2.3.4")
	proxy.OnEndpointsAdd(ep1)

	err = mainProxy.assertEvents("after creating first endpoints",
		"add endpoints testns/one 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after creating first endpoints",
		"add endpoints testns/one 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Idle the service; both the service and the endpoints will be removed from the
	// main proxy, and the service will be added to the unidling proxy.
	svc1idled := svc1.DeepCopy()
	svc1idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnServiceUpdate(svc1, svc1idled)
	ep1idled := ep1.DeepCopy()
	ep1idled.Subsets[0].Addresses = nil
	ep1idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnEndpointsUpdate(ep1, ep1idled)

	err = mainProxy.assertEvents("after idling first service",
		"update service testns/one",
		"delete service testns/one",
		"update endpoints testns/one -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after idling first service",
		"add service testns/one",
		"update endpoints testns/one -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Unidle the service, reverting the previous change
	proxy.OnServiceUpdate(svc1idled, svc1)
	proxy.OnEndpointsUpdate(ep1idled, ep1)

	err = mainProxy.assertEvents("after unidling first service",
		"add service testns/one",
		"update endpoints testns/one 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after unidling first service",
		"update service testns/one",
		"delete service testns/one",
		"update endpoints testns/one 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Modify the endpoints; both proxies will see the change
	ep1modified := makeEndpoints("testns", "one", "5.6.7.8")
	proxy.OnEndpointsUpdate(ep1, ep1modified)

	err = mainProxy.assertEvents("after modifying first service",
		"update endpoints testns/one 5.6.7.8",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after modifying first service",
		"update endpoints testns/one 5.6.7.8",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// *****

	// Create another service, but this time create the endpoints first
	ep2 := makeEndpoints("testns", "two", "9.10.11.12")
	proxy.OnEndpointsAdd(ep2)

	err = mainProxy.assertEvents("after creating second endpoints",
		"add endpoints testns/two 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after creating second endpoints",
		"add endpoints testns/two 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now create the service
	svc2 := makeService("testns", "two")
	err = createServiceAndWait(svc2, proxy)
	if err != nil {
		t.Fatalf("unexpected error creating service: %v", err)
	}
	proxy.OnServiceAdd(svc2)

	err = mainProxy.assertEvents("after creating second service",
		"add service testns/two",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after creating second endpoints")
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Idle, then unidle the service
	ep2idled := ep2.DeepCopy()
	ep2idled.Subsets[0].Addresses = nil
	ep2idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnEndpointsUpdate(ep2, ep2idled)
	svc2idled := svc2.DeepCopy()
	svc2idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnServiceUpdate(svc2, svc2idled)

	err = mainProxy.assertEvents("after idling second service",
		"delete service testns/two",
		"update endpoints testns/two -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after idling second service",
		"add service testns/two",
		"update service testns/two",
		"update endpoints testns/two -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	proxy.OnEndpointsUpdate(ep2idled, ep2)
	proxy.OnServiceUpdate(svc2idled, svc2)

	err = mainProxy.assertEvents("after unidling second service",
		"add service testns/two",
		"update service testns/two",
		"update endpoints testns/two 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after unidling second service",
		"delete service testns/two",
		"update endpoints testns/two 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// ****

	// Create a Service, then its Endpoints, then empty its Endpoints and idle it,
	// then delete the Service while it's idle.

	svc3 := makeService("testns", "three")
	err = createServiceAndWait(svc3, proxy)
	if err != nil {
		t.Fatalf("unexpected error creating service: %v", err)
	}
	proxy.OnServiceAdd(svc3)

	err = mainProxy.assertEvents("after creating third service",
		"add service testns/three",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after creating third service")
	if err != nil {
		t.Fatalf("%v", err)
	}

	ep3 := makeEndpoints("testns", "three", "1.2.3.4")
	proxy.OnEndpointsAdd(ep3)

	err = mainProxy.assertEvents("after creating third endpoints",
		"add endpoints testns/three 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after creating third endpoints",
		"add endpoints testns/three 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	svc3idled := svc3.DeepCopy()
	svc3idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnServiceUpdate(svc3, svc3idled)
	ep3idled := ep3.DeepCopy()
	ep3idled.Subsets[0].Addresses = nil
	ep3idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnEndpointsUpdate(ep3, ep3idled)

	err = mainProxy.assertEvents("after idling third service",
		"update service testns/three",
		"delete service testns/three",
		"update endpoints testns/three -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after idling third service",
		"add service testns/three",
		"update endpoints testns/three -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now delete it
	err = deleteServiceAndWait(svc3idled, proxy)
	if err != nil {
		t.Fatalf("unexpected error deleting service: %v", err)
	}
	proxy.OnServiceDelete(svc3idled)

	err = mainProxy.assertNoEvents("after deleting third service")
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after deleting third service",
		"delete service testns/three",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// And its endpoints
	proxy.OnEndpointsDelete(ep3idled)

	err = mainProxy.assertEvents("after deleting third endpoints",
		"delete endpoints testns/three -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after deleting third endpoints",
		"delete endpoints testns/three -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// ****

	// Clean up
	proxy.OnEndpointsDelete(ep1modified)

	err = deleteServiceAndWait(svc2, proxy)
	if err != nil {
		t.Fatalf("unexpected error deleting service: %v", err)
	}
	proxy.OnServiceDelete(svc2)

	proxy.OnEndpointsDelete(ep2)

	err = deleteServiceAndWait(svc1, proxy)
	if err != nil {
		t.Fatalf("unexpected error deleting service: %v", err)
	}
	proxy.OnServiceDelete(svc1)

	err = mainProxy.assertEvents("after cleanup",
		"delete service testns/one",
		"delete endpoints testns/one 5.6.7.8",
		"delete service testns/two",
		"delete endpoints testns/two 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after cleanup",
		"delete endpoints testns/one 5.6.7.8",
		"delete endpoints testns/two 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}
