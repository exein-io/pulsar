#!/usr/bin/env sh

# Run to build a compile_commands.json, which useful for auto-completion engines 
(
first=1
echo -n "["
for source in */*/*.bpf.c
do
  if test $first -eq 1
  then
    first=0
  else
    echo ","
  fi
  workspace=$(realpath $(dirname ${source}))
  dir=$(realpath $(dirname ${source}))
  workspace=$(realpath "${dir}/../..")
  name=$(basename ${source})
  echo "{"
  echo "  \"directory\": \"${dir}\","
  echo "  \"file\": \"${name}\","
  echo "  \"arguments\": ["
	echo "    \"/usr/bin/clang\","
	echo "    \"-I${workspace}/bpf-common/include/\","
	echo "    \"-I${workspace}/bpf-common/include/x86_64/\","
	echo "    \"-g\","
	echo "    \"-O2\","
	echo "    \"-D__TARGET_ARCH_x86\","
	echo "    \"-c\","
	echo "    \"-o /tmp/file.o\","
	echo "    \"${name}\""
  echo "  ]"
  echo -n "}"
done
echo "]"
) | tee compile_commands.json
