#define PY_SSIZE_T_CLEAN
#include <Python.h>

uint8_t calculation_buf[8192];

//TODO: Add callback impl so we can have a fun challenge :))
static PyObject* err_callback;

static PyObject* compress(PyObject *self, PyObject *args) {
    Py_buffer buffer;
    if(!PyArg_ParseTuple(args, "y*", &buffer)) {
        return NULL;
    }

    
    if(buffer.len <= 0) {
        if (err_callback) {
            PyObject* arglist = Py_BuildValue("(s)", "Invalid length during compression");
            PyObject* result = PyObject_CallObject(err_callback, arglist);
            Py_XDECREF(arglist);
        }
        return NULL;
    }
    const char* data = buffer.buf;

    size_t ptr = 0;
    uint8_t prev = data[0];
    uint8_t count = 1;
    for(size_t i = 1 ; i < buffer.len ; i++) {
        if (data[i] == prev && count < 0xff) {
            count++;
        } else {
            calculation_buf[ptr++] = count;
            calculation_buf[ptr++] = prev;
            prev = data[i];
            count = 1;
        }
    }
    calculation_buf[ptr++] = count;
    calculation_buf[ptr++] = prev;

    PyBuffer_Release(&buffer);
    return PyBytes_FromStringAndSize((char*)calculation_buf, ptr);
}

static PyObject* decompress(PyObject *self, PyObject *args) {
    Py_buffer buffer;
    if(!PyArg_ParseTuple(args, "y*", &buffer)) {
        return NULL;
    }

    if(buffer.len <= 1 || buffer.len % 2 != 0) {
        if (err_callback) {
            PyObject* arglist = Py_BuildValue("(s)", "Invalid length during decompression");
            PyObject* result = PyObject_CallObject(err_callback, arglist);
            Py_XDECREF(arglist);
        }
        return NULL;
    }

    const char* data = buffer.buf;

    size_t ptr = 0;
    for(size_t i = 0 ; i < buffer.len ; i+=2) {
        uint8_t count = data[i];
        char c = data[i+1];
        for(size_t j = 0 ; j < count ; j++) {
            calculation_buf[ptr++] = c;
        }
    }

    PyBuffer_Release(&buffer);
    return PyBytes_FromStringAndSize((char*)calculation_buf, ptr);
}

static PyObject*
set_err_callback(PyObject *self, PyObject *args) {
    PyObject* obj = NULL;

    if(!PyArg_ParseTuple(args, "O:set_callback", &obj)) {
        return NULL;
    }

    if(!PyCallable_Check(obj)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable !");
        return NULL;
    }

    Py_XINCREF(obj);
    Py_XDECREF(err_callback);
    err_callback = obj;
    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef CompressMethods[] = {
	{ "compress", compress, METH_VARARGS, "Compresses a file into a .cc that is smaller !" },
	{ "decompress", decompress, METH_VARARGS, "Deompresses a file into a file that is bigger !" },
	{ "set_err_callback", set_err_callback, METH_VARARGS, "Sets the callaback to handle various errors" },
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef summodule = {
	PyModuleDef_HEAD_INIT,
	"cool_compress",
	NULL,
	-1,
	CompressMethods
};

PyMODINIT_FUNC PyInit_cool_compress(void) {
	return PyModule_Create(&summodule);
}
