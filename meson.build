project('benchmark', ['c'],
    version : '1.0.0',
    meson_version : '>= 0.61.2',
    default_options : [
        'warning_level=3',
        'buildtype=release',
        'optimization=3',
        'debug=true',
        'strip=true',
        'b_lto=true',
        'cpp_std=c++17',
        'c_std=c11',
        'c_args=-O3',
        'c_link_args=-O3',
        'default_library=both',
        'prefix=/usr/local/musl',
    ],
)

# Specify the include directories
include_directories = include_directories('include')

# Check for headers
cc = meson.get_compiler('c')
pthread_dep = cc.find_library('pthread', required : true)
argp_dep = cc.find_library('argp', required : false)
seccomp_dep = dependency('seccomp', required : false)
check_dep = dependency('check', required : true)
zlib_dep = dependency('zlib', required : false)
mxml_dep = dependency('mxml', required : false)
vmpl_dep = dependency('vmpl', required : false)

# Specify the target and source files for the hello_world project
# Specify the linker flags and the libraries
bench_sources = files(
    'src/benchmark.c',
    'src/server.c',
    'src/client.c',
    'src/bench/bench_dune_ring.c',
    'src/semaphore_test.c',
    'src/test_bitmap.c',
)

bench_deps = [
    pthread_dep,
    argp_dep,
    seccomp_dep,
    check_dep,
    zlib_dep,
]

# Conditional compilation
if zlib_dep.found()
    bench_sources += files('src/test_zlib.c')
    bench_deps += zlib_dep
endif

if mxml_dep.found()
    bench_sources += files('src/test_mxml.c')
    bench_deps += mxml_dep
endif

if argp_dep.found()
    bench_sources += files('src/test_argp.c')
    bench_deps += argp_dep
endif

if seccomp_dep.found()
    bench_sources += files('src/test_seccomp.c')
    bench_deps += seccomp_dep
endif

bench = executable('bench',
                    bench_sources,
                    dependencies : bench_deps,
                    c_args : ['-Wall', '-g', '-MD', '-O2', '-z', 'noexecstack'],
                    include_directories : include_directories)

# Other executables
hello = executable('hello',
                    'src/hello.c',
                    dependencies : vmpl_dep,
                    include_directories : include_directories)

fork = executable('fork', 'src/fork.c',
                    dependencies : pthread_dep,
                    include_directories : include_directories)

timetest = executable('timetest', 'src/timetest.c',
                    dependencies : pthread_dep,
                    include_directories : include_directories)

tests = executable('tests', 'src/test.c',
                    dependencies : [ pthread_dep, vmpl_dep ],
                    include_directories : include_directories)