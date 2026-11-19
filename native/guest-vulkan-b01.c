#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <vulkan/vulkan.h>

static void log_to_stderr(const struct __android_log_message *message) {
    fprintf(stderr, "android[%s/%d] %s\n", message->tag, message->priority, message->message);
}

static void print_result(const char *call, VkResult result) {
    printf("%s -> %d%s\n", call, result,
           result == VK_SUCCESS ? " VK_SUCCESS" :
           result == VK_ERROR_INITIALIZATION_FAILED ? " VK_ERROR_INITIALIZATION_FAILED" : "");
}

static int print_pastel_mapping(struct dl_phdr_info *info, size_t size, void *found) {
    (void)size;
    const char *name = strrchr(info->dlpi_name, '/');
    if (name && !strcmp(name + 1, "vulkan.pastel.so")) {
        printf("mapped ICD %s\n", info->dlpi_name);
        *(int *)found = 1;
    }
    return 0;
}

static int create_device(void *loader, VkPhysicalDevice physical) {
    PFN_vkGetPhysicalDeviceQueueFamilyProperties families =
        (PFN_vkGetPhysicalDeviceQueueFamilyProperties)dlsym(loader, "vkGetPhysicalDeviceQueueFamilyProperties");
    PFN_vkCreateDevice create = (PFN_vkCreateDevice)dlsym(loader, "vkCreateDevice");
    PFN_vkDestroyDevice destroy = (PFN_vkDestroyDevice)dlsym(loader, "vkDestroyDevice");
    if (!families || !create || !destroy) {
        fputs("device creation: Vulkan loader exports missing\n", stderr);
        return 2;
    }
    uint32_t count = 0;
    families(physical, &count, NULL);
    printf("queue family count=%u\n", count);
    if (!count)
        return 1;
    VkQueueFamilyProperties *queues = calloc(count, sizeof *queues);
    if (!queues)
        return 2;
    families(physical, &count, queues);
    uint32_t family = UINT32_MAX;
    for (uint32_t i = 0; i < count; ++i) {
        printf("queue family %u count=%u flags=0x%x\n", i, queues[i].queueCount, queues[i].queueFlags);
        if (family == UINT32_MAX && queues[i].queueCount &&
            (queues[i].queueFlags & VK_QUEUE_GRAPHICS_BIT))
            family = i;
    }
    free(queues);
    if (family == UINT32_MAX) {
        fputs("device creation: no graphics queue family\n", stderr);
        return 1;
    }
    const float priority = 1.0f;
    const VkDeviceQueueCreateInfo queue = {
        .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex = family,
        .queueCount = 1,
        .pQueuePriorities = &priority,
    };
    const VkDeviceCreateInfo info = {
        .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount = 1,
        .pQueueCreateInfos = &queue,
    };
    VkDevice device = VK_NULL_HANDLE;
    printf("call vkCreateDevice(queueFamily=%u, no enabled extensions)\n", family);
    VkResult result = create(physical, &info, NULL, &device);
    print_result("vkCreateDevice", result);
    if (result != VK_SUCCESS || device == VK_NULL_HANDLE)
        return 1;
    destroy(device, NULL);
    puts("vkDestroyDevice: completed");
    return 0;
}

#define LOAD(name) \
    PFN_##name name = (PFN_##name)dlsym(loader, #name); \
    if (!name) { fprintf(stderr, "dlsym(%s): %s\n", #name, dlerror()); return 2; }

int main(int argc, char **argv) {
    int expect_pastel = argc == 2 && !strcmp(argv[1], "--pastel-device");
    if (argc != 1 && !expect_pastel) {
        fprintf(stderr, "usage: %s [--pastel-device]\n", argv[0]);
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    __android_log_set_logger(log_to_stderr);
    __android_log_set_minimum_priority(ANDROID_LOG_VERBOSE);

    const char *keys[] = {"ro.hardware.vulkan", "ro.board.platform", "ro.vulkan.apex",
                          "ro.hardware"};
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; ++i) {
        char value[PROP_VALUE_MAX];
        int length = __system_property_get(keys[i], value);
        printf("property %s=%s\n", keys[i], length ? value : "<empty>");
    }

    void *loader = dlopen("/system/lib64/libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (!loader) {
        fprintf(stderr, "dlopen(libvulkan.so): %s\n", dlerror());
        return 2;
    }
    puts("dlopen(/system/lib64/libvulkan.so): OK");
    LOAD(vkEnumerateInstanceExtensionProperties);
    LOAD(vkCreateInstance);
    LOAD(vkDestroyInstance);
    LOAD(vkEnumeratePhysicalDevices);
    LOAD(vkGetPhysicalDeviceProperties);
    LOAD(vkEnumerateDeviceExtensionProperties);

    puts("call vkEnumerateInstanceExtensionProperties(count)");
    uint32_t count = 0;
    VkResult result = vkEnumerateInstanceExtensionProperties(NULL, &count, NULL);
    print_result("vkEnumerateInstanceExtensionProperties(count)", result);
    int pastel_mapped = 0;
    if (expect_pastel)
        dl_iterate_phdr(print_pastel_mapping, &pastel_mapped);
    printf("instance extension count=%u\n", count);
    if (result != VK_SUCCESS)
        return 1;
    if (count) {
        VkExtensionProperties *extensions = calloc(count, sizeof *extensions);
        if (!extensions)
            return 2;
        result = vkEnumerateInstanceExtensionProperties(NULL, &count, extensions);
        print_result("vkEnumerateInstanceExtensionProperties(list)", result);
        for (uint32_t i = 0; result == VK_SUCCESS && i < count; ++i)
            printf("instance extension %s specVersion=%u\n", extensions[i].extensionName,
                   extensions[i].specVersion);
        free(extensions);
        if (result != VK_SUCCESS)
            return 1;
    }

    const VkApplicationInfo application = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "ssal-vulkan-b01",
        .apiVersion = VK_API_VERSION_1_0,
    };
    const VkInstanceCreateInfo info = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &application,
    };
    VkInstance instance = VK_NULL_HANDLE;
    puts("call vkCreateInstance(apiVersion=1.0, no layers or extensions)");
    result = vkCreateInstance(&info, NULL, &instance);
    print_result("vkCreateInstance", result);
    if (result != VK_SUCCESS)
        return 1;
    if (instance == VK_NULL_HANDLE) {
        fputs("vkCreateInstance returned VK_SUCCESS with VK_NULL_HANDLE\n", stderr);
        return 1;
    }

    puts("call vkEnumeratePhysicalDevices(count)");
    count = 0;
    result = vkEnumeratePhysicalDevices(instance, &count, NULL);
    print_result("vkEnumeratePhysicalDevices(count)", result);
    printf("physical device count=%u\n", count);
    if (result != VK_SUCCESS || !count) {
        vkDestroyInstance(instance, NULL);
        return 1;
    }

    VkPhysicalDevice *devices = calloc(count, sizeof *devices);
    if (!devices) {
        vkDestroyInstance(instance, NULL);
        return 2;
    }
    result = vkEnumeratePhysicalDevices(instance, &count, devices);
    print_result("vkEnumeratePhysicalDevices(list)", result);
    int exit_code = result == VK_SUCCESS && count ? 0 : 1;
    int pastel_device = 0;
    for (uint32_t i = 0; result == VK_SUCCESS && i < count; ++i) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(devices[i], &props);
        printf("physical device %u: %s type=%d vendor=%04x device=%04x apiVersion=%u.%u.%u\n",
               i, props.deviceName, props.deviceType, props.vendorID, props.deviceID,
               VK_API_VERSION_MAJOR(props.apiVersion), VK_API_VERSION_MINOR(props.apiVersion),
               VK_API_VERSION_PATCH(props.apiVersion));
        printf("physical device %u driverVersion=%u\n", i, props.driverVersion);
        if (expect_pastel && pastel_mapped && !pastel_device &&
            props.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU && strstr(props.deviceName, "SwiftShader")) {
            pastel_device = 1;
            int status = create_device(loader, devices[i]);
            if (status)
                exit_code = status;
        }
        uint32_t size = 0;
        VkResult ext_result = vkEnumerateDeviceExtensionProperties(devices[i], NULL, &size, NULL);
        print_result("vkEnumerateDeviceExtensionProperties(count)", ext_result);
        if (ext_result != VK_SUCCESS) {
            exit_code = 1;
            continue;
        }
        if (!size)
            continue;
        VkExtensionProperties *extensions = calloc(size, sizeof *extensions);
        if (!extensions) {
            exit_code = 2;
            break;
        }
        ext_result = vkEnumerateDeviceExtensionProperties(devices[i], NULL, &size, extensions);
        print_result("vkEnumerateDeviceExtensionProperties(list)", ext_result);
        for (uint32_t j = 0; ext_result == VK_SUCCESS && j < size; ++j)
            printf("device %u extension %s specVersion=%u\n", i, extensions[j].extensionName,
                   extensions[j].specVersion);
        free(extensions);
        if (ext_result != VK_SUCCESS)
            exit_code = 1;
    }
    free(devices);
    vkDestroyInstance(instance, NULL);
    if (expect_pastel && !pastel_device) {
        fputs("expected mapped Pastel and a SwiftShader CPU physical device\n", stderr);
        return 1;
    }
    return exit_code;
}
