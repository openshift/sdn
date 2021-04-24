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
	proxy, mainProxy, unidlingProxy, err := newTestOsdnProxy(true)
	if err != nil {
		t.Fatalf("unexpected error creating OsdnProxy: %v", err)
	}
	hybridProxy := proxy.baseProxy.(*HybridProxier)

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

	// Then create its endpoints.
	_, slice1 := makeEndpoints("testns", "one", "1.2.3.4")
	proxy.OnEndpointSliceAdd(slice1)

	err = mainProxy.assertEvents("after creating first endpoints",
		"add endpointslice testns/one 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after creating first endpoints")
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Idle the service; both the service and the endpoints will be removed from the
	// main proxy, and the service will be added to the unidling proxy.
	svc1idled := svc1.DeepCopy()
	svc1idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnServiceUpdate(svc1, svc1idled)

	// Because a service needs both an annotation and empty endpoints in order to
	// become idle, it should not be idle yet (which means also that the service
	// update gets passed through).
	err = mainProxy.assertEvents("after annotating service but not removing endpoints",
		"update service testns/one",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after annotating service but not removing endpoints")
	if err != nil {
		t.Fatalf("%v", err)
	}

	slice1idled := slice1.DeepCopy()
	slice1idled.Endpoints[0].Addresses = nil
	proxy.OnEndpointSliceUpdate(slice1, slice1idled)

	err = mainProxy.assertEvents("after idling first service",
		"delete service testns/one",
		"update endpointslice testns/one -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after idling first service",
		"add service testns/one",
		"add endpoints testns/one -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Unidle the service, reverting the previous change. This time neither proxy
	// sees the "service update testns/one" because removing the annotation immediately
	// unidles the service, so that event gets translated into the delete/add.
	proxy.OnServiceUpdate(svc1idled, svc1)
	proxy.OnEndpointSliceUpdate(slice1idled, slice1)

	err = mainProxy.assertEvents("after unidling first service",
		"add service testns/one",
		"update endpointslice testns/one 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after unidling first service",
		"delete service testns/one",
		"update endpoints testns/one 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Modify the endpoints; the unidling proxy will see the change since
	// the Service is still in the Unidling state
	_, slice1modified := makeEndpoints("testns", "one", "5.6.7.8")
	proxy.OnEndpointSliceUpdate(slice1, slice1modified)

	err = mainProxy.assertEvents("after modifying first service",
		"update endpointslice testns/one 5.6.7.8",
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

	// Fake out the passage of time and do another update; now the unidling
	// proxy should see it as a delete
	svcName := ktypes.NamespacedName{Namespace: "testns", Name: "one"}
	hsvc := hybridProxy.getService(svcName)
	expiredTime := time.Now().Add(-time.Hour)
	hsvc.unidledAt = &expiredTime
	hybridProxy.releaseService(svcName)

	_, slice1modified2 := makeEndpoints("testns", "one", "9.10.11.12")
	proxy.OnEndpointSliceUpdate(slice1modified, slice1modified2)

	mainProxy.assertEvents("after re-modifying first service",
		"update endpointslice testns/one 9.10.11.12",
	)
	unidlingProxy.assertEvents("after re-modifying first service",
		"delete endpoints testns/one 5.6.7.8",
	)

	// Change the endpoints back; the unidling proxy should not see the event
	proxy.OnEndpointSliceUpdate(slice1, slice1modified)

	mainProxy.assertEvents("after re-re-modifying first service",
		"update endpointslice testns/one 5.6.7.8",
	)
	unidlingProxy.assertNoEvents("after re-re-modifying first service")

	// *****

	// Create another service, but this time create the endpoints first
	_, slice2 := makeEndpoints("testns", "two", "9.10.11.12")
	proxy.OnEndpointSliceAdd(slice2)

	err = mainProxy.assertEvents("after creating second endpoints",
		"add endpointslice testns/two 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after creating second endpoints")
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
	slice2idled := slice2.DeepCopy()
	slice2idled.Endpoints[0].Addresses = nil
	proxy.OnEndpointSliceUpdate(slice2, slice2idled)
	svc2idled := svc2.DeepCopy()
	svc2idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnServiceUpdate(svc2, svc2idled)

	err = mainProxy.assertEvents("after idling second service",
		"delete service testns/two",
		"update endpointslice testns/two -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after idling second service",
		"add service testns/two",
		"add endpoints testns/two -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Since we modify the EndpointSlice first this time, the service will be unidled
	// then, and so the Service change will be seen by the main proxy.
	proxy.OnEndpointSliceUpdate(slice2idled, slice2)
	proxy.OnServiceUpdate(svc2idled, svc2)

	err = mainProxy.assertEvents("after unidling second service",
		"add service testns/two",
		"update service testns/two",
		"update endpointslice testns/two 9.10.11.12",
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

	// Create a Service, then its EndpointSlice, then empty its EndpointSlice and idle
	// it, then delete the Service while it's idle.

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

	_, slice3 := makeEndpoints("testns", "three", "1.2.3.4")
	proxy.OnEndpointSliceAdd(slice3)

	err = mainProxy.assertEvents("after creating third endpoints",
		"add endpointslice testns/three 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after creating third endpoints")
	if err != nil {
		t.Fatalf("%v", err)
	}

	svc3idled := svc3.DeepCopy()
	svc3idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnServiceUpdate(svc3, svc3idled)
	slice3idled := slice3.DeepCopy()
	slice3idled.Endpoints[0].Addresses = nil
	proxy.OnEndpointSliceUpdate(slice3, slice3idled)

	err = mainProxy.assertEvents("after idling third service",
		"update service testns/three",
		"delete service testns/three",
		"update endpointslice testns/three -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after idling third service",
		"add service testns/three",
		"add endpoints testns/three -",
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
	proxy.OnEndpointSliceDelete(slice3idled)

	err = mainProxy.assertEvents("after deleting third endpoints",
		"delete endpointslice testns/three -",
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
	proxy.OnEndpointSliceDelete(slice1modified)

	err = deleteServiceAndWait(svc2, proxy)
	if err != nil {
		t.Fatalf("unexpected error deleting service: %v", err)
	}
	proxy.OnServiceDelete(svc2)

	proxy.OnEndpointSliceDelete(slice2)

	err = deleteServiceAndWait(svc1, proxy)
	if err != nil {
		t.Fatalf("unexpected error deleting service: %v", err)
	}
	proxy.OnServiceDelete(svc1)

	err = mainProxy.assertEvents("after cleanup",
		"delete service testns/one",
		"delete endpointslice testns/one 5.6.7.8",
		"delete service testns/two",
		"delete endpointslice testns/two 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after cleanup",
		"delete endpoints testns/two 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestHybridProxyPreIdled(t *testing.T) {
	proxy, mainProxy, unidlingProxy, err := newTestOsdnProxy(true)
	if err != nil {
		t.Fatalf("unexpected error creating OsdnProxy: %v", err)
	}

	// Create a Service which is already idled when it is first created

	_, slicepi := makeEndpoints("testns", "pre-idled")
	proxy.OnEndpointSliceAdd(slicepi)

	svcpi := makeService("testns", "pre-idled")
	svcpi.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	err = createServiceAndWait(svcpi, proxy)
	if err != nil {
		t.Fatalf("unexpected error creating service: %v", err)
	}
	proxy.OnServiceAdd(svcpi)

	err = mainProxy.assertEvents("after creating pre-idled service",
		"add endpointslice testns/pre-idled -",
		"add service testns/pre-idled",
		"delete service testns/pre-idled",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after creating pre-idled service",
		"add service testns/pre-idled",
		"add endpoints testns/pre-idled -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now un-idle the service
	svcpiUnidled := makeService("testns", "pre-idled")
	proxy.OnServiceUpdate(svcpi, svcpiUnidled)
	_, slicepiUnidled := makeEndpoints("testns", "pre-idled", "1.2.3.4")
	proxy.OnEndpointSliceUpdate(slicepi, slicepiUnidled)

	err = mainProxy.assertEvents("after unidling pre-idled service",
		"add service testns/pre-idled",
		"update endpointslice testns/pre-idled 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after unidling pre-idled service",
		"delete service testns/pre-idled",
		"update endpoints testns/pre-idled 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now delete it
	err = deleteServiceAndWait(svcpiUnidled, proxy)
	if err != nil {
		t.Fatalf("unexpected error deleting service: %v", err)
	}
	proxy.OnServiceDelete(svcpiUnidled)
	proxy.OnEndpointSliceDelete(slicepiUnidled)

	err = mainProxy.assertEvents("after deleting pre-idled service",
		"delete service testns/pre-idled",
		"delete endpointslice testns/pre-idled 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after deleting pre-idled service",
		"delete endpoints testns/pre-idled 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestHybridProxyReIdling(t *testing.T) {
	proxy, mainProxy, unidlingProxy, err := newTestOsdnProxy(true)
	if err != nil {
		t.Fatalf("unexpected error creating OsdnProxy: %v", err)
	}
	hybridProxy := proxy.baseProxy.(*HybridProxier)

	// ****

	// Create a Service, idle and unidle it, then re-idle it again while it's still in
	// the Unidling state.

	svcri := makeService("testns", "re-idle")
	err = createServiceAndWait(svcri, proxy)
	if err != nil {
		t.Fatalf("unexpected error creating service: %v", err)
	}
	proxy.OnServiceAdd(svcri)

	_, sliceri := makeEndpoints("testns", "re-idle", "1.2.3.4")
	proxy.OnEndpointSliceAdd(sliceri)

	err = mainProxy.assertEvents("after creating re-idling service",
		"add service testns/re-idle",
		"add endpointslice testns/re-idle 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after creating re-idle service")
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Idle and then un-idle the service
	_, sliceriIdled := makeEndpoints("testns", "re-idle")
	proxy.OnEndpointSliceUpdate(sliceri, sliceriIdled)
	svcriIdled := svcri.DeepCopy()
	svcriIdled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnServiceUpdate(svcri, svcriIdled)

	err = mainProxy.assertEvents("after idling re-idle service",
		"delete service testns/re-idle",
		"update endpointslice testns/re-idle -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after idling re-idle service",
		"add service testns/re-idle",
		"add endpoints testns/re-idle -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	proxy.OnServiceUpdate(svcriIdled, svcri)
	proxy.OnEndpointSliceUpdate(sliceriIdled, sliceri)

	err = mainProxy.assertEvents("after unidling re-idle service",
		"add service testns/re-idle",
		"update endpointslice testns/re-idle 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after unidling re-idle service",
		"delete service testns/re-idle",
		"update endpoints testns/re-idle 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now re-idle the Service; note in particular that the unidling proxy
	// should see an "update endpoints" event this time.
	proxy.OnEndpointSliceUpdate(sliceri, sliceriIdled)
	proxy.OnServiceUpdate(svcri, svcriIdled)

	err = mainProxy.assertEvents("after re-idling re-idle service",
		"delete service testns/re-idle",
		"update endpointslice testns/re-idle -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after re-idling re-idle service",
		"add service testns/re-idle",
		"update endpoints testns/re-idle -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Unidle
	proxy.OnServiceUpdate(svcriIdled, svcri)
	proxy.OnEndpointSliceUpdate(sliceriIdled, sliceri)

	err = mainProxy.assertEvents("after unidling re-idle service",
		"add service testns/re-idle",
		"update endpointslice testns/re-idle 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after unidling re-idle service",
		"delete service testns/re-idle",
		"update endpoints testns/re-idle 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Fake out the passage of time...
	svcName := ktypes.NamespacedName{Namespace: "testns", Name: "re-idle"}
	hsvc := hybridProxy.getService(svcName)
	expiredTime := time.Now().Add(-time.Hour)
	hsvc.unidledAt = &expiredTime
	hybridProxy.releaseService(svcName)

	// Idle again; because the Unidling period expired this time, the events on the
	// unidlingProxy are slightly different this time

	proxy.OnEndpointSliceUpdate(sliceri, sliceriIdled)
	proxy.OnServiceUpdate(svcri, svcriIdled)

	err = mainProxy.assertEvents("after re-idling re-idle service after time passed",
		"delete service testns/re-idle",
		"update endpointslice testns/re-idle -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after re-idling re-idle service after time passed",
		"add service testns/re-idle",
		"delete endpoints testns/re-idle 1.2.3.4",
		"add endpoints testns/re-idle -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// More time passes
	svcName = ktypes.NamespacedName{Namespace: "testns", Name: "re-idle"}
	hsvc = hybridProxy.getService(svcName)
	expiredTime = time.Now().Add(-time.Hour)
	hsvc.unidledAt = &expiredTime
	hybridProxy.releaseService(svcName)

	// And delete it
	err = deleteServiceAndWait(svcriIdled, proxy)
	if err != nil {
		t.Fatalf("unexpected error deleting service: %v", err)
	}
	proxy.OnServiceDelete(svcriIdled)
	proxy.OnEndpointSliceDelete(sliceriIdled)

	err = mainProxy.assertEvents("after deleting re-idle service",
		"delete endpointslice testns/re-idle -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after deleting re-idle service",
		"delete service testns/re-idle",
		"delete endpoints testns/re-idle -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestHybridProxyNoSlices(t *testing.T) {
	proxy, mainProxy, unidlingProxy, err := newTestOsdnProxy(false)
	if err != nil {
		t.Fatalf("unexpected error creating OsdnProxy: %v", err)
	}
	hybridProxy := proxy.baseProxy.(*HybridProxier)

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

	// Then create its endpoints.
	ep1, _ := makeEndpoints("testns", "one", "1.2.3.4")
	proxy.OnEndpointsAdd(ep1)

	err = mainProxy.assertEvents("after creating first endpoints",
		"add endpoints testns/one 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after creating first endpoints")
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Idle the service; both the service and the endpoints will be removed from the
	// main proxy, and the service will be added to the unidling proxy.
	svc1idled := svc1.DeepCopy()
	svc1idled.Annotations[unidlingapi.IdledAtAnnotation] = "now"
	proxy.OnServiceUpdate(svc1, svc1idled)

	// Because a service needs both an annotation and empty endpoints in order to
	// become idle, it should not be idle yet (which means also that the service
	// update gets passed through).
	err = mainProxy.assertEvents("after annotating service but not removing endpoints",
		"update service testns/one",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after annotating service but not removing endpoints")
	if err != nil {
		t.Fatalf("%v", err)
	}

	ep1idled := ep1.DeepCopy()
	ep1idled.Subsets[0].Addresses = nil
	proxy.OnEndpointsUpdate(ep1, ep1idled)

	err = mainProxy.assertEvents("after idling first service",
		"delete service testns/one",
		"update endpoints testns/one -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after idling first service",
		"add service testns/one",
		"add endpoints testns/one -",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Unidle the service, reverting the previous change. This time neither proxy
	// sees the "service update testns/one" because removing the annotation immediately
	// unidles the service, so that event gets translated into the delete/add.
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
		"delete service testns/one",
		"update endpoints testns/one 1.2.3.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Modify the endpoints; the unidling proxy will see the change since
	// the Service is still in the Unidling state
	ep1modified, _ := makeEndpoints("testns", "one", "5.6.7.8")
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

	// Fake out the passage of time and do another update; now the unidling
	// proxy should see it as a delete
	svcName := ktypes.NamespacedName{Namespace: "testns", Name: "one"}
	hsvc := hybridProxy.getService(svcName)
	expiredTime := time.Now().Add(-time.Hour)
	hsvc.unidledAt = &expiredTime
	hybridProxy.releaseService(svcName)

	ep1modified2, _ := makeEndpoints("testns", "one", "9.10.11.12")
	proxy.OnEndpointsUpdate(ep1modified, ep1modified2)

	err = mainProxy.assertEvents("after re-modifying first service",
		"update endpoints testns/one 9.10.11.12",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertEvents("after re-modifying first service",
		"delete endpoints testns/one 5.6.7.8",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Change the endpoints back; the unidling proxy should not see the event
	proxy.OnEndpointsUpdate(ep1, ep1modified)

	err = mainProxy.assertEvents("after re-re-modifying first service",
		"update endpoints testns/one 5.6.7.8",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after re-re-modifying first service")
	if err != nil {
		t.Fatalf("%v", err)
	}

	// ****

	// Clean up
	proxy.OnEndpointsDelete(ep1modified)

	err = deleteServiceAndWait(svc1, proxy)
	if err != nil {
		t.Fatalf("unexpected error deleting service: %v", err)
	}
	proxy.OnServiceDelete(svc1)

	err = mainProxy.assertEvents("after cleanup",
		"delete service testns/one",
		"delete endpoints testns/one 5.6.7.8",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = unidlingProxy.assertNoEvents("after cleanup")
	if err != nil {
		t.Fatalf("%v", err)
	}
}
