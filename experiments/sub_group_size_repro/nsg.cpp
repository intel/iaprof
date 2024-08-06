#include <sycl/sycl.hpp>

int main() {
  auto const& gpu_devices = sycl::device::get_devices(sycl::info::device_type::gpu);
  std::cout << "Number of Root GPUs: " << gpu_devices.size() << std::endl;

  for(const auto& d : gpu_devices) {
    std::cout << "Found Root GPU-ID: " << d.get_info<sycl::info::device::name>() << std::endl;
    std::vector<size_t> sg_sizes = d.get_info<sycl::info::device::sub_group_sizes>();
    std::cout << "Supported sub-group sizes: ";
    for (int i=0; i<sg_sizes.size(); i++) {
      std::cout << sg_sizes[i] << " ";
    }
    std::cout << std::endl;
  }

  const int N{1024};
  sycl::queue Q{sycl::gpu_selector{}};
  int* ptr = sycl::malloc_device<int>(N, Q);
  Q.parallel_for(N, [=](sycl::item<1> id) { ptr[id] = id; }).wait();
  return 0;
}
