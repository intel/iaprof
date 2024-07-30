#include <level_zero/zet_api.h>

int main()
{
        ze_result_t status;
        ze_device_handle_t device;
        ze_driver_handle_t driver;

        status = zeInit(0);
        if (status != ZE_RESULT_SUCCESS) {
                std::cerr << "zeInit failed with: " << std::hex << status
                          << std::dec << std::endl;
                return 1;
        }

        device = utils::ze::GetGpuDevice();
        driver = utils::ze::GetGpuDriver();
        if (device == nullptr || driver == nullptr) {
                std::cout << "Unable to find GPU device" << std::endl;
                return 1;
        }

        retval = zetDebugAttach(device, );
}
