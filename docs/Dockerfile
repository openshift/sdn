FROM centos:8
LABEL authors="Daniel Mellado<dmellado@redhat.com>"

RUN yum upgrade -y \
    && yum install -y --setopt=tsflags=nodocs python3-pip libstdc++ \
    && yum install -y --setopt=tsflags=nodocs gcc gcc-c++ python3-devel

COPY . /opt/sdn_docs

RUN pip3 install -U pip \
    && yum -y history undo last \
    && yum clean all

RUN python3 -m pip install -r /opt/sdn_docs/requirements.txt
RUN sphinx-build -W -b html /opt/sdn_docs/source /opt/sdn_docs/build/html
RUN rm -rf /opt/sdn_docs/source

WORKDIR /opt/sdn_docs/build/html
EXPOSE  80
ENTRYPOINT ["python3", "-m", "http.server", "80"]
