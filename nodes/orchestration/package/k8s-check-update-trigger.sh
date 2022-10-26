#!/bin/bash

while read line;
do
   date > /etc/cp/conf/k8s-policy-check.trigger
done
