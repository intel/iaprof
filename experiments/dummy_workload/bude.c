#include <float.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <cassert>
#include <string>
#include <vector>
#include <iga/kv.hpp>

/* #include "print_elf_sections.h" */

#if defined(__APPLE__)
  #include <OpenCL/OpenCL.h>
#else
  #include <CL/cl.h>
  #include <omp.h>
#endif

#define MAX_PLATFORMS     8
#define MAX_DEVICES      32
#define MAX_INFO_STRING 256
#define MAX_STR_SIZE 4096

#define DATA_DIR          "./data/bm1"
#define FILE_LIGAND       "/ligand.in"
#define FILE_PROTEIN      "/protein.in"
#define FILE_FORCEFIELD   "/forcefield.in"
#define FILE_POSES        "/poses.in"
#define FILE_REF_ENERGIES "/ref_energies.out"

#define REF_NPOSES 65536

#define FILE_KERNEL     "budeMultiTD.cl"

// Energy evaluation parameters
#define CNSTNT   45.0f
#define HBTYPE_F 70
#define HBTYPE_E 69
#define HARDNESS 38.0f
#define NPNPDIST  5.5f
#define NPPDIST   1.0f

extern "C" {

typedef struct
{
  cl_float x, y, z;
  cl_int   type;
} Atom;

typedef struct
{
  cl_int   hbtype;
  cl_float radius;
  cl_float hphb;
  cl_float elsc;
} FFParams;

struct
{
  cl_int    natlig;
  cl_int    natpro;
  cl_int    ntypes;
  cl_int    nposes;
  Atom     * protein;
  Atom     * ligand;
  FFParams * forcefield;
  float    * poses[6];

  int iterations;
  int run_omp;
} params = {0};

struct
{
  cl_device_id     device;
  cl_context       context;
  cl_command_queue queue;
  cl_program       program;
  cl_kernel        kernel;

  int              deviceIndex;
  int              wgsize;
  int              posesPerWI;
  char            *deckDir;
} cl = {0};

};

extern "C" double   getTimestamp();
void     loadParameters(int argc, char *argv[]);
void     freeParameters();
void     printTimings(double start, double end, double poses_per_wi);

extern "C" void     initCL();
unsigned getDevices(cl_device_id devices[MAX_DEVICES]);
void     getDeviceName(cl_device_id device, char name[MAX_INFO_STRING]);
void     releaseCL();
void     checkError(cl_int err, const char *op);

void     runOpenMP(float *energies);
void     runOpenCL(float *energies);

std::vector< std::pair<uint32_t, std::string> > Disassemble(
    uint8_t *binary, size_t binary_size) {
  std::vector< std::pair<uint32_t, std::string> > instruction_list;

  KernelView kv(IGA_GEN11, binary, binary_size,
                iga::SWSB_ENCODE_MODE::SingleDistPipe);
  assert(kv.decodeSucceeded());

  char text[MAX_STR_SIZE] = { 0 };
  int32_t offset = 0, size = 0;
  while (true) {
    size = kv.getInstSize(offset);
    if (size == 0) {
      break;
    }

    size_t lenght = kv.getInstSyntax(offset, text, MAX_STR_SIZE);
    assert(lenght > 0);
    instruction_list.push_back(std::make_pair(offset, text));

    offset += size;
  }

  return instruction_list;
}

extern "C" FILE* openFile(const char *parent, const char *child,
               const char* mode, long *length)
{
  char name[strlen(parent) + strlen(child) + 1];
  strcpy(name, parent);
  strcat(name, child);

  FILE *file = NULL;
  if (!(file = fopen(name, mode)))
  {
    fprintf(stderr, "Failed to open '%s'\n", name);
    exit(1);
  }
  if(length){
    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    rewind(file);
  }
  return file;
}

extern "C" int main(int argc, char *argv[])
{
  loadParameters(argc, argv);
  printf("\n");
  printf("Poses     : %d\n", params.nposes);
  printf("Iterations: %d\n", params.iterations);
  printf("Ligands   : %d\n", params.natlig);
  printf("Proteins  : %d\n", params.natpro);
  printf("Deck      : %s\n", cl.deckDir);
  float maxdiff      = -100.0f;
  size_t n_ref_poses = params.nposes;

  float *energiesOCL = (float *) malloc(params.nposes*sizeof(float));
  float *energiesOMP = (float *) malloc(params.nposes*sizeof(float));

  runOpenCL(energiesOCL);

  if (params.run_omp)
    runOpenMP(energiesOMP);
  else {
    // Load reference results from file

    FILE* ref_energies = openFile(cl.deckDir, FILE_REF_ENERGIES, "r", NULL);
    if (params.nposes > REF_NPOSES) {
      printf("Only validating the first %d poses.\n", REF_NPOSES);
      n_ref_poses = REF_NPOSES;
    }

    for (size_t i = 0; i < n_ref_poses; i++)
      fscanf(ref_energies, "%f", &energiesOMP[i]);

    fclose(ref_energies);
  }


  // Verify results
  if (params.run_omp)
    printf("\n OpenMP          OpenCL   (diff)\n");
  else
    printf("\n Reference       OpenCL   (diff)\n");

  for (int i = 0; i < n_ref_poses; i++)
  {
    if (fabs(energiesOMP[i]) < 1. && fabs(energiesOCL[i]) < 1.f)
      continue;

    float diff = fabs(energiesOMP[i] - energiesOCL[i]) / energiesOCL[i];
    if (diff > maxdiff)
      maxdiff = diff;

    if (i < 8)
    {
      printf("%7.2f    vs   %7.2f  (%5.2f%%)\n",
            energiesOMP[i], energiesOCL[i], 100*diff);
    }
  }

  printf("\nLargest difference was %.3f%%\n\n", maxdiff);

  free(energiesOCL);
  free(energiesOMP);

  freeParameters();
}

void runOpenMP(float *results)
{
  printf("\nRunning C/OpenMP\n");

  double start = getTimestamp();

#pragma omp parallel
  for (int itr = 0; itr < params.iterations; itr++)
  {
#pragma omp for
    for (unsigned i = 0; i < params.nposes; i++)
    {
      float etot = 0;

      // Compute transformation matrix
      const float sx = sin(params.poses[0][i]);
      const float cx = cos(params.poses[0][i]);
      const float sy = sin(params.poses[1][i]);
      const float cy = cos(params.poses[1][i]);
      const float sz = sin(params.poses[2][i]);
      const float cz = cos(params.poses[2][i]);

      float transform[3][4];
      transform[0][0] = cy*cz;
      transform[0][1] = sx*sy*cz - cx*sz;
      transform[0][2] = cx*sy*cz + sx*sz;
      transform[0][3] = params.poses[3][i];
      transform[1][0] = cy*sz;
      transform[1][1] = sx*sy*sz + cx*cz;
      transform[1][2] = cx*sy*sz - sx*cz;
      transform[1][3] = params.poses[4][i];
      transform[2][0] = -sy;
      transform[2][1] = sx*cy;
      transform[2][2] = cx*cy;
      transform[2][3] = params.poses[5][i];

      // Loop over ligand atoms
      int il = 0;
      do
      {
        // Load ligand atom data
        const Atom l_atom = params.ligand[il];
        const FFParams l_params = params.forcefield[l_atom.type];
        const int lhphb_ltz = l_params.hphb<0.f;
        const int lhphb_gtz = l_params.hphb>0.f;

        // Transform ligand atom
        float lpos_x = transform[0][3]
          + l_atom.x * transform[0][0]
          + l_atom.y * transform[0][1]
          + l_atom.z * transform[0][2];
        float lpos_y = transform[1][3]
          + l_atom.x * transform[1][0]
          + l_atom.y * transform[1][1]
          + l_atom.z * transform[1][2];
        float lpos_z = transform[2][3]
          + l_atom.x * transform[2][0]
          + l_atom.y * transform[2][1]
          + l_atom.z * transform[2][2];

        // Loop over protein atoms
        int ip = 0;
        do
        {
          // Load protein atom data
          const Atom p_atom = params.protein[ip];
          const FFParams p_params = params.forcefield[p_atom.type];

          const float radij   = p_params.radius + l_params.radius;
          const float r_radij = 1.f / radij;

          const float elcdst  =
            (p_params.hbtype==HBTYPE_F && l_params.hbtype==HBTYPE_F)
            ? 4.f : 2.f;
          const float elcdst1 =
            (p_params.hbtype==HBTYPE_F && l_params.hbtype==HBTYPE_F)
            ? 0.25f : 0.5f;
          const int   type_E  =
            ((p_params.hbtype==HBTYPE_E || l_params.hbtype==HBTYPE_E));

          const int  phphb_ltz = p_params.hphb <  0.f;
          const int  phphb_gtz = p_params.hphb >  0.f;
          const int  phphb_nz  = p_params.hphb != 0.f;
          const float p_hphb   =
            p_params.hphb * (phphb_ltz && lhphb_gtz ? -1.f : 1.f);
          const float l_hphb   =
            l_params.hphb * (phphb_gtz && lhphb_ltz ? -1.f : 1.f);
          const float distdslv =
            (phphb_ltz ? (lhphb_ltz ? NPNPDIST : NPPDIST)
              : (lhphb_ltz ? NPPDIST : -FLT_MAX));
          const float r_distdslv = 1.f / distdslv;

          const float chrg_init = l_params.elsc * p_params.elsc;
          const float dslv_init = p_hphb + l_hphb;

          // Calculate distance between atoms
          const float x      = lpos_x - p_atom.x;
          const float y      = lpos_y - p_atom.y;
          const float z      = lpos_z - p_atom.z;
          const float distij = sqrt(x*x + y*y + z*z);

          // Calculate the sum of the sphere radii
          const float distbb = distij - radij;
          const int  zone1   = (distbb < 0.f);

          // Calculate steric energy
          etot += (1.f - (distij*r_radij)) * (zone1 ? 2*HARDNESS : 0.f);

          // Calculate formal and dipole charge interactions
          float chrg_e = chrg_init
            * ((zone1 ? 1 : (1.f - distbb*elcdst1))
              * (distbb<elcdst ? 1 : 0.f));
          float neg_chrg_e = -fabs(chrg_e);
          chrg_e = type_E ? neg_chrg_e : chrg_e;
          etot  += chrg_e*CNSTNT;

          // Calculate the two cases for Nonpolar-Polar repulsive interactions
          float coeff  = (1.f - (distbb*r_distdslv));
          float dslv_e = dslv_init * ((distbb<distdslv && phphb_nz) ? 1 : 0.f);
          dslv_e *= (zone1 ? 1 : coeff);
          etot   += dslv_e;

        } while (++ip < params.natpro); // loop over protein atoms
      } while (++il < params.natlig); // loop over ligand atoms

      // Write result
      results[i] = etot*0.5f;
    }
  }

  double end = getTimestamp();

  printTimings(start, end, 1);
}

void runOpenCL(float *results)
{
  printf("\nRunning OpenCL\n");

  initCL();

  cl_int err;
  cl_mem protein, ligand, energies, forcefield, poses[6];

  // Create buffers
  protein = clCreateBuffer(cl.context, CL_MEM_READ_ONLY,
                           params.natpro*sizeof(Atom), NULL, &err);
  checkError(err, "creating protein");

  ligand = clCreateBuffer(cl.context, CL_MEM_READ_ONLY,
                          params.natlig*sizeof(Atom), NULL, &err);
  checkError(err, "creating ligand");

  energies = clCreateBuffer(cl.context, CL_MEM_WRITE_ONLY,
                            params.nposes*sizeof(cl_float), NULL, &err);
  checkError(err, "creating energies");

  forcefield = clCreateBuffer(cl.context, CL_MEM_READ_ONLY,
                              params.ntypes*sizeof(FFParams), NULL, &err);
  checkError(err, "creating forcefield");

  for (int i = 0; i < 6; i++)
  {
    poses[i] = clCreateBuffer(cl.context, CL_MEM_READ_ONLY,
                              params.nposes*sizeof(cl_float), NULL, &err);
  }

  // Write data to device
  err = clEnqueueWriteBuffer(cl.queue, protein, CL_TRUE, 0,
                             params.natpro*sizeof(Atom), params.protein,
                             0, NULL, NULL);
  checkError(err, "writing protein");
  err = clEnqueueWriteBuffer(cl.queue, ligand, CL_TRUE, 0,
                             params.natlig*sizeof(Atom), params.ligand,
                             0, NULL, NULL);
  checkError(err, "writing ligand");
  err = clEnqueueWriteBuffer(cl.queue, forcefield, CL_TRUE, 0,
                             params.ntypes*sizeof(FFParams), params.forcefield,
                             0, NULL, NULL);
  checkError(err, "writing forcefield");

  for (int i = 0; i < 6; i++)
  {
    err = clEnqueueWriteBuffer(cl.queue, poses[i], CL_TRUE, 0,
                               params.nposes*sizeof(cl_float), params.poses[i],
                               0, NULL, NULL);
    checkError(err, "writing poses");
  }

  // Set kernel arguments
  err  = clSetKernelArg(cl.kernel, 0, sizeof(cl_int), &params.natlig);
  err |= clSetKernelArg(cl.kernel, 1, sizeof(cl_int), &params.natpro);
  err |= clSetKernelArg(cl.kernel, 2, sizeof(cl_mem), &protein);
  err |= clSetKernelArg(cl.kernel, 3, sizeof(cl_mem), &ligand);
  err |= clSetKernelArg(cl.kernel, 4, sizeof(cl_mem), poses+0);
  err |= clSetKernelArg(cl.kernel, 5, sizeof(cl_mem), poses+1);
  err |= clSetKernelArg(cl.kernel, 6, sizeof(cl_mem), poses+2);
  err |= clSetKernelArg(cl.kernel, 7, sizeof(cl_mem), poses+3);
  err |= clSetKernelArg(cl.kernel, 8, sizeof(cl_mem), poses+4);
  err |= clSetKernelArg(cl.kernel, 9, sizeof(cl_mem), poses+5);
  err |= clSetKernelArg(cl.kernel, 10, sizeof(cl_mem), &energies);
  err |= clSetKernelArg(cl.kernel, 11, sizeof(cl_mem), &forcefield);
  err |= clSetKernelArg(cl.kernel, 12, params.ntypes*sizeof(FFParams), NULL);
  err |= clSetKernelArg(cl.kernel, 13, sizeof(cl_int), &params.ntypes);
  err |= clSetKernelArg(cl.kernel, 14, sizeof(cl_int), &params.nposes);
  checkError(err, "setting arguments");

  size_t global = ceil(params.nposes/(double)cl.posesPerWI);
         global = cl.wgsize * ceil(global/(double)cl.wgsize);
  size_t local  = cl.wgsize;

  // Warm-up run (not timed)
  err = clEnqueueNDRangeKernel(cl.queue, cl.kernel, 1, NULL,
                               &global, &local, 0, NULL, NULL);
  checkError(err, "queuing kernel");
  err = clFinish(cl.queue);
  checkError(err, "running kernel");

  double start = getTimestamp();

  // Timed runs
  for (int i = 0; i < params.iterations; i++)
  {
    err = clEnqueueNDRangeKernel(cl.queue, cl.kernel, 1, NULL,
                                 &global, &local, 0, NULL, NULL);
  }

  err = clFinish(cl.queue);
  checkError(err, "running kernel");

  double end = getTimestamp();

  // Read results
  err = clEnqueueReadBuffer(cl.queue, energies, CL_TRUE, 0,
                            params.nposes*sizeof(cl_float), results,
                            0, NULL, NULL);
  checkError(err, "reading results");

  printTimings(start, end, cl.posesPerWI);

  clReleaseMemObject(protein);
  clReleaseMemObject(ligand);
  clReleaseMemObject(energies);
  clReleaseMemObject(forcefield);
  clReleaseMemObject(poses[0]);
  clReleaseMemObject(poses[1]);
  clReleaseMemObject(poses[2]);
  clReleaseMemObject(poses[3]);
  clReleaseMemObject(poses[4]);
  clReleaseMemObject(poses[5]);

  releaseCL();
}

int parseInt(const char *str)
{
  char *next;
  int value = strtoul(str, &next, 10);
  return strlen(next) ? -1 : value;
}

void loadParameters(int argc, char *argv[])
{
  // Defaults
  params.iterations = 8;
  params.run_omp    = 0;
  cl.wgsize         = 64;
  cl.posesPerWI     = 4;
  cl.deckDir        = DATA_DIR;
  int nposes        = 65536;

  for (int i = 1; i < argc; i++)
  {
    if (!strcmp(argv[i], "--list") || !strcmp(argv[i], "-l"))
    {
      // Get list of devices
      cl_device_id devices[MAX_DEVICES];
      unsigned numDevices = getDevices(devices);

      // Print device names
      if (numDevices == 0)
      {
        printf("No devices found.\n");
      }
      else
      {
        printf("\n");
        printf("Devices:\n");
        for (int i = 0; i < numDevices; i++)
        {
          char name[MAX_INFO_STRING];
          getDeviceName(devices[i], name);
          printf("%2d: %s\n", i, name);
        }
        printf("\n");
      }
      exit(0);
    }
    else if (!strcmp(argv[i], "--device") || !strcmp(argv[i], "-d"))
    {
      if (++i >= argc || (cl.deviceIndex = parseInt(argv[i])) < 0)
      {
        printf("Invalid device index\n");
        exit(1);
      }
    }
    else if (!strcmp(argv[i], "--iterations") || !strcmp(argv[i], "-i"))
    {
      if (++i >= argc || (params.iterations = parseInt(argv[i])) < 0)
      {
        printf("Invalid number of iterations\n");
        exit(1);
      }
    }
    else if (!strcmp(argv[i], "--numposes") || !strcmp(argv[i], "-n"))
    {
      if (++i >= argc || (nposes = parseInt(argv[i])) < 0)
      {
        printf("Invalid number of poses\n");
        exit(1);
      }
    }
    else if (!strcmp(argv[i], "--posesperwi") || !strcmp(argv[i], "-p"))
    {
      if (++i >= argc || (cl.posesPerWI = parseInt(argv[i])) < 0)
      {
        printf("Invalid poses-per-workitem value\n");
        exit(1);
      }
    }
    else if (!strcmp(argv[i], "--wgsize") || !strcmp(argv[i], "-w"))
    {
      if (++i >= argc || (cl.wgsize = parseInt(argv[i])) < 0)
      {
        printf("Invalid work-group size\n");
        exit(1);
      }
    }
    else if (!strcmp(argv[i], "--deck"))
    {
      if (++i >= argc)
      {
        printf("Invalid deck\n");
        exit(1);
      }
      cl.deckDir = argv[i];
    }
    else if (!strcmp(argv[i], "--openmp"))
    {
      params.run_omp = 1;
    }
    else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h"))
    {
      printf("\n");
      printf("Usage: ./bude [OPTIONS]\n\n");
      printf("Options:\n");
      printf("  -h  --help               Print this message\n");
      printf("      --list               List available devices\n");
      printf("  -d  --device     INDEX   Select device at INDEX\n");
      printf("  -i  --iterations I       Repeat kernel I times\n");
      printf("  -n  --numposes   N       Compute energies for N poses\n");
      printf("  -p  --poserperwi PPWI    Compute PPWI poses per work-item\n");
      printf("  -w  --wgsize     WGSIZE  Run with work-group size WGSIZE\n");
      printf("      --deck       DECK    Use the DECK directory as input deck\n");
      printf("      --openmp             Validate results against a reference OpenMP implementation\n");
      printf("\n");
      exit(0);
    }
    else
    {
      printf("Unrecognized argument '%s' (try '--help')\n", argv[i]);
      exit(1);
    }
  }

  FILE *file = NULL;
  long length;

  struct stat s;
  int e = stat(cl.deckDir, &s);
  if(e == -1 || !S_ISDIR(s.st_mode)){
    printf("Cannot stat or not a directory: %s\n", cl.deckDir);
    exit(1);
  }

  file = openFile(cl.deckDir, FILE_LIGAND, "rb", &length);
  params.natlig = length / sizeof(Atom);
  params.ligand = (Atom *) malloc(params.natlig*sizeof(Atom));
  fread(params.ligand, sizeof(Atom), params.natlig, file);
  fclose(file);

  file = openFile(cl.deckDir, FILE_PROTEIN, "rb", &length);
  params.natpro = length / sizeof(Atom);
  params.protein = (Atom *) malloc(params.natpro*sizeof(Atom));
  fread(params.protein, sizeof(Atom), params.natpro, file);
  fclose(file);

  file = openFile(cl.deckDir, FILE_FORCEFIELD, "rb", &length);
  params.ntypes = length / sizeof(FFParams);
  params.forcefield = (FFParams *) malloc(params.ntypes*sizeof(FFParams));
  fread(params.forcefield, sizeof(FFParams), params.ntypes, file);
  fclose(file);

  file = openFile(cl.deckDir, FILE_POSES, "rb", &length);
  for (int i = 0; i < 6; i++)
    params.poses[i] = (float *) malloc(nposes*sizeof(float));

  long available = length / 6 / sizeof(float);
  params.nposes = 0;
  while (params.nposes < nposes)
  {
    long fetch = nposes - params.nposes;
    if (fetch > available)
      fetch = available;

    for (int i = 0; i < 6; i++)
    {
      fseek(file, i*available*sizeof(float), SEEK_SET);
      fread(params.poses[i] + params.nposes, sizeof(float), fetch, file);
    }
    rewind(file);

    params.nposes += fetch;
  }
  fclose(file);
}

void freeParameters()
{
  free(params.ligand);
  free(params.protein);
  free(params.forcefield);
  for (int i = 0; i < 6; i++)
    free(params.poses[i]);
}

void printTimings(double start, double end, double poses_per_wi)
{
  double ms = ((end-start)/params.iterations)*1e-3;

  // Compute FLOP/s
  double runtime   = ms*1e-3;
  double ops_per_wi = 27*poses_per_wi
    + params.natlig*(3 + 18*poses_per_wi + params.natpro*(11 + 30*poses_per_wi))
    + poses_per_wi;
  double total_ops     = ops_per_wi * (params.nposes/poses_per_wi);
  double flops      = total_ops / runtime;
  double gflops     = flops / 1e9;

  double interactions         =
      (double)params.nposes
    * (double)params.natlig
    * (double)params.natpro;
  double interactions_per_sec = interactions / runtime;

  // Print stats
  printf("- Total time:     %7.2lf ms\n", (end-start)*1e-3);
  printf("- Average time:   %7.2lf ms\n", ms);
  printf("- Interactions/s: %7.2lf billion\n", (interactions_per_sec / 1e9));
  printf("- GFLOP/s:        %7.2lf\n", gflops);
}

void checkError(cl_int err, const char *op)
{
  if (err != CL_SUCCESS)
  {
    printf("Error during operation '%s' (%d)\n", op, err);
    releaseCL();
  }
}

unsigned getDevices(cl_device_id devices[MAX_DEVICES])
{
  cl_int err;

  // Get list of platforms
  cl_uint numPlatforms = 0;
  cl_platform_id platforms[MAX_PLATFORMS];
  err = clGetPlatformIDs(MAX_PLATFORMS, platforms, &numPlatforms);
  checkError(err, "getting platforms");

  // Enumerate devices
  unsigned numDevices = 0;
  for (int i = 0; i < numPlatforms; i++)
  {
    cl_uint num = 0;
    err = clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_ALL,
                         MAX_DEVICES-numDevices, devices+numDevices, &num);
    checkError(err, "getting deviceS");
    numDevices += num;
  }

  return numDevices;
}

void getDeviceName(cl_device_id device, char name[MAX_INFO_STRING])
{
  cl_device_info info = CL_DEVICE_NAME;

  // Special case for AMD
#ifdef CL_DEVICE_BOARD_NAME_AMD
  clGetDeviceInfo(device, CL_DEVICE_VENDOR, MAX_INFO_STRING, name, NULL);
  if (strstr(name, "Advanced Micro Devices"))
    info = CL_DEVICE_BOARD_NAME_AMD;
#endif

  clGetDeviceInfo(device, info, MAX_INFO_STRING, name, NULL);
}

extern "C" double getTimestamp()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_usec + tv.tv_sec*1e6;
}

extern "C" void initCL()
{
  cl_int err;

  cl_device_id devices[MAX_DEVICES];
  unsigned num = getDevices(devices);
  if (cl.deviceIndex >= num)
  {
    printf("Invalid device index (try '--list')\n");
    exit(1);
  }
  cl.device = devices[cl.deviceIndex];

  char name[128];
  getDeviceName(cl.device, name);
  printf("Using device: %s\n", name);

  cl.context = clCreateContext(NULL, 1, &cl.device, NULL, NULL, &err);
  checkError(err, "creating context");

  cl.queue = clCreateCommandQueue(
    cl.context, cl.device, CL_QUEUE_PROFILING_ENABLE, &err);
  checkError(err, "creating queue");

  long length;
  FILE *file = openFile("./", FILE_KERNEL, "r", &length);
  char *source = (char *) malloc(length+1);
  fread(source, 1, length, file);
  source[length] = '\0';
  fclose(file);

  cl.program = clCreateProgramWithSource(
    cl.context, 1, (const char**)&source, NULL, &err);
  checkError(err, "creating program");

  char options[256];
  sprintf(options,
          "-cl-fast-relaxed-math -cl-mad-enable -DNUM_TD_PER_THREAD=%d",
          cl.posesPerWI);
  err = clBuildProgram(cl.program, 1, &cl.device, options, NULL, NULL);
  if (err != CL_SUCCESS)
  {
    if (err == CL_BUILD_PROGRAM_FAILURE)
    {
      char log[16384];
      clGetProgramBuildInfo(cl.program, cl.device, CL_PROGRAM_BUILD_LOG,
                            16384, log, NULL);
      printf("%s\n", log);
    }
  }
  free(source);
  checkError(err, "building program");

  cl.kernel = clCreateKernel(cl.program, "fasten_main", &err);
  checkError(err, "creating kernel");
  
  /* Get the binary of the GPU kernel */
/*   size_t *binary_size = malloc(sizeof(size_t)); */
/*   err = clGetProgramInfo(cl.program, CL_PROGRAM_BINARY_SIZES, */
/*                           1 * sizeof(size_t), */
/*                           binary_size, NULL); */
/*   checkError(err, "getting program info"); */

/*   uint8_t **binary = malloc(sizeof(uint8_t *)); */
/*   for (size_t i = 0; i < 1; ++i) { */
/*     binary[i] = malloc(sizeof(uint8_t) * binary_size[i]); */
/*   } */

/*   err = clGetProgramInfo(cl.program, CL_PROGRAM_BINARIES, */
/*                             1 * sizeof(uint8_t*), */
/*                             binary, NULL); */
/*   checkError(err, "getting program binary"); */

  #define CL_KERNEL_BINARY_PROGRAM_INTEL 0x407D


  size_t binary_size = 0;
  err = clGetKernelInfo(cl.kernel, CL_KERNEL_BINARY_PROGRAM_INTEL,
                        0, NULL, &binary_size);
  checkError(err, "getting binary size");
  
  unsigned char* binary = (unsigned char *) malloc(sizeof(unsigned char) * binary_size);
  err = clGetKernelInfo(cl.kernel, CL_KERNEL_BINARY_PROGRAM_INTEL,
                        binary_size, binary, NULL);
  checkError(err, "getting binary");
  
  int n;
  for(n = 0; n < binary_size; ++n) {
    printf("%02x ", binary[n], ( n + 1 ) % 2 == 0 ? "\n" : " " );
    if((n + 1) % 16 == 0) {
      printf("\n");
    } else if((n + 1) % 8 == 0) {
      printf(" ");
    }
  }
  FILE *file_ptr;
  file_ptr = fopen("tmp", "wb");
  fwrite(binary, binary_size, 1, file_ptr);
  
/*   Disassemble(binary, binary_size); */
}

#define RELEASE(func, obj) if (obj) {func(obj); obj=NULL;};
void releaseCL()
{
  RELEASE(clReleaseKernel, cl.kernel);
  RELEASE(clReleaseProgram, cl.program);
  RELEASE(clReleaseCommandQueue, cl.queue);
  RELEASE(clReleaseContext, cl.context);
}
