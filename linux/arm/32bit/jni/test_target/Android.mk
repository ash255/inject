LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := test_target
LOCAL_SRC_FILES := test_target.c 

LOCAL_LDLIBS := -llog 

#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)
