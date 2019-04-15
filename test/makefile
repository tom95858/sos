INSTPATH=/home/tom/opt/ovis
CFLAGS = -g -fPIC \
	-I$(INSTPATH)/include \
	-L$(INSTPATH)/lib64 -lsos -shared

value_data_test.so : value_data_test.c
	$(CC) $< -o $@ $(CFLAGS)
