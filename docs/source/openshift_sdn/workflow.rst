====================
Development Workflow
====================

Get the code
------------

.. code-block:: shell-session

  $ git clone https://github.com/openshift/openshift-sdn.git
  $ git clone https://github.com/openshift/cluster-network-operator.git

Do your changes
---------------

Create the image
----------------

.. code-block:: shell-session

  $ make build-image-sdn-test

This will call podman under the hood and it'll create an image with your
changes for openshift/sdn

Push your image to quay.io
--------------------------

.. code-block:: shell-session

  $ podman push sdn-test quay.io/<your_quay_user>/sdn-test:latest
  Getting image source signatures
  Copying blob 5d372c8d2def done
  Copying blob f8c626b0e778 done
  Copying blob 660ab9198463 done
  Copying blob 9ed8d791092a done
  Copying blob b174dfe5972b done
  Copying blob 0ccfac04663b skipped: already exists
  Copying blob 577bed1928c2 done
  Copying blob d2af519c9d8e done
  Copying blob 25cd2a8f7dec done
  Copying blob 08fc1691d013 done
  Copying blob 95b8292eb455 done
  Copying config cff2b47201 done
  Writing manifest to image destination
  Copying config cff2b47201 [--------------------------------------] 0.0b / 4.5KiB
  Writing manifest to image destination
  Writing manifest to image destination
  Storing signatures

Deploy a cluster with your changes
----------------------------------

Using Cluster Network Operator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 1. Create a directory for your deployment

  .. code-block:: shell-session

    $ mkdir /tmp/deployment


 2. Get your openshift-install binary and your pull-secrets

 3. Go to your Cluster Network Operator (CNO) Directory

 4. Run hack/run-locally

  .. code-block:: shell-session

    $ hack/run-locally.sh -i <your_openshift_install_path> -c <your_install_directory> -n <sdn|ovn> -m <your_quay_image_path>

Using Cluster-Bot
~~~~~~~~~~~~~~~~~

This assumes you already have a PR around, and access to cluster-bot under the
CoreOS Slack channel.

Just query cluster-bot and send him a message with the following::

  launch openshift/sdn#<PR_NUMBER> aws

Update your CNO image without deleting your cluster
---------------------------------------------------

.. code-block:: shell-session

  update_cno ()
  {
      oc patch clusterversion version --type json -p '[{"op":"add","path":"/spec/overrides","value":[{"kind":"Deployment","group":"apps","name":"network-operator","namespace":"openshift-network-operator","unmanaged":true}]}]'
  }

  custom_sdn ()
  {
      update_cno;
      oc -n openshift-network-operator delete deployment network-operator;
      oc -n openshift-sdn set image ds/sdn sdn=quay.io/<your_quay_user>/sdn-test
  }

Destroying your cluster once you're done
----------------------------------------

Using Openshift Installer
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: shell-session

  $ openshift-install destroy cluster --dir <your_install_directory>

Using Cluster-Bot
~~~~~~~~~~~~~~~~~
::

  done
