/*
    clang++ -fsycl -o be.bin basic_esimd.cpp       // <-- SPIR-V works everywhere (including PVC)

    clang++ -fsycl -fsycl-targets=spir64_gen -Xs '-device pvc' -o be_pvc.bin basic_esimd.cpp     // <-- AoT not working PVC


    clang++ -fsycl -fsycl-targets=spir64_gen -Xs '-device gen9' -o be_gen9.bin basic_esimd.cpp   // <--- AoT Works Gen9


    AoT doesn't seem to work with simd. Not just copy_from but possibly any at all. 
 

*/
#include <CL/sycl.hpp>
#include <sycl/ext/intel/esimd.hpp>
//#include <sycl/ext/intel/experimental/esimd.hpp>
using namespace sycl;
//using namespace sycl::ext::intel::experimental::esimd;
using namespace sycl::ext::intel::esimd;

using EType = float;


int main(){
    constexpr unsigned Size = 1024;
    constexpr unsigned VL = 32;
    constexpr unsigned GroupSize = 8;

    queue q(gpu_selector{});

    EType *A = malloc_shared<EType>(Size, q);
    EType *B = malloc_shared<EType>(Size, q);
    EType *C = malloc_shared<EType>(Size, q);

    for (unsigned i = 0; i != Size; i++) {
      A[i] = B[i] = i;
    }

    q.submit([&](handler &cgh) {
      cgh.parallel_for<class Test>(/*Size / VL*/32,
        [=](id<1> i)  [[intel::sycl_explicit_simd]]  {
        auto offset = i * VL;

        
        // this works, SPIRV & Gen9 AOT
        // simd<float, VL> va(A + offset);
        // simd<float, VL> vb(B + offset);

        // this works SPIRV & Gen9 AOT.
        simd<EType, VL> va;
        simd<EType, VL> vb;
        va.copy_from(A+offset);
        vb.copy_from(B+offset);



        simd<EType, VL> vc = va + vb;
        vc.copy_to(C + offset);
      });
    }).wait();


    for(int i=0; i < Size; i++){
        if(i % 16 == 0){ std::cout << std::endl; }
        std::cout << C[i] << " ";
    }
    std::cout << std::endl;

    free(A, q);
    free(B, q);
    free(C, q);


    return 0;
}
