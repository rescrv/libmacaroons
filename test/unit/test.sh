#/bin/ash

files=`find . -type f -name "serializa*" -not -name "*.sh"`

for f in ${files}
do
	echo ${f}
	../../build/serialize_test < ${f}
done

