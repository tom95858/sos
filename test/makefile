INSTPATH=/home/tom/opt/ovis
CFLAGS = -g -fPIC \
	-I$(INSTPATH)/include \
	-L$(INSTPATH)/lib64 -lsos -shared


all : value_data_test.so obj_malloc_test.so

value_data_test.so : value_data_test.c
	$(CC) $< -o $@ $(CFLAGS)

obj_malloc_test.so : obj_malloc_test.c
	$(CC) $< -o $@ $(CFLAGS)
