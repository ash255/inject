LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := test_so
LOCAL_SRC_FILES := test_so.c
#LOCAL_C_INCLUDES := test_so.h

LOCAL_LDLIBS := -llog 
#LOCAL_CPPFLAGS:=-std=c++11

include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)
