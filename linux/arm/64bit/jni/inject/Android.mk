LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := inject
LOCAL_SRC_FILES := inject.c ptrace.c
LOCAL_C_INCLUDES := ptrace.h

LOCAL_LDLIBS := -llog 

#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)
