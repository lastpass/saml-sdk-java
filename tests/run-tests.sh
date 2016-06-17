#!/bin/bash

CP=../classes
for i in ../lib/*.jar ../out/*jar; do
    CP=$CP:$i
done

jruby -J-cp $CP -S rspec *_spec.rb
