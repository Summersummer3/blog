# TEE知识集合

## optee

### CA->TA

CA是调用TEE安全服务的入口程序，运行在非安全用户态el0。

TA是TEE服务的重点，大部分自定义的安全服务在TA中实现，运行在安全用户态SEL0.

从CA到TA的invoke command，完成一次服务调用，将会经历一个漫长的层级及CPU安全态切换，通常的通路如下：

​	     (链接)						  (ioctl)                         (smc指令)		 (el3 eret sel1)                     (sel1 eret)

CA========>libteec.so=======>tee_driver=========>ATF==========>TEE_kernel==========>TA

若TEE/TA服务有部分工作需要返回非安全态执行，则需要返回tee_driver呼叫非安全侧守护进程tee_supplicant去完成工作：

TA/TEE_kernel====>ATF====>tee_driver====>tee_supplicant

由于ATF主要工作是在启动阶段完成，运行态时主要用于切换CPU安全/非安全状态，保存/恢复彼此的寄存器状态上下文，不在此处细聊。下面我们将通过一次TA加载过程的数据流来细讲每一个组件的主要功能。



#### libteec.so

libteec.so中包含了GP标准下提供的五个供CA调用与TA通讯的接口：

```c
TEEC_Result TEEC_InitializeContext(
    const char* name,
    TEEC_Context* context)

void TEEC_FinalizeContext(
    TEEC_Context* context)

TEEC_Result TEEC_OpenSession (
    TEEC_Context* context,
    TEEC_Session* session,
    const TEEC_UUID* destination,
    uint32_t connectionMethod,
    const void* connectionData,
    TEEC_Operation* operation,
    uint32_t* returnOrigin)

void TEEC_CloseSession (
    TEEC_Session* session)

TEEC_Result TEEC_InvokeCommand(
    TEEC_Session* session,
    uint32_t commandID,
    TEEC_Operation* operation,
    uint32_t* returnOrigin)
```

可以看到成对出现的ctx和session操作以及服务调用的`TEEC_InvokeCommand`。

调用TEE中TA的服务第一步是打开TEE驱动：可以看到`TEEC_InitializeContext`操作是很简单的，尝试去打开tee_driver的字符设备，teec的上下文中将驱动的描述符存下来，供后续使用; 并查询了一些驱动中保存的TEE_OS的一些版本信息.

```C
TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *ctx)
{
	char devname[PATH_MAX] = { 0 };
	int fd = 0;
	size_t n = 0;

	if (!ctx)
		return TEEC_ERROR_BAD_PARAMETERS;
	
	for (n = 0; n < TEEC_MAX_DEV_SEQ; n++) {
		uint32_t gen_caps = 0;
	
		snprintf(devname, sizeof(devname), "/dev/tee%zu", n); //通常tee驱动只会创建一个设备，自定义条件下可能有多个设备。
		fd = teec_open_dev(devname, name, &gen_caps);//尝试去打开tee_driver的驱动
		if (fd >= 0) {
			ctx->fd = fd; //将设备的文件描述符存储在上下文中
			ctx->reg_mem = gen_caps & TEE_GEN_CAP_REG_MEM;  //获取驱动关于tee的版本相关信息，不关键
			ctx->memref_null = gen_caps & TEE_GEN_CAP_MEMREF_NULL;
			return TEEC_SUCCESS;
		}
	}
	
	return TEEC_ERROR_ITEM_NOT_FOUND;

}

static int teec_open_dev(const char *devname, const char *capabilities,
			 uint32_t *gen_caps)
{
	int fd = 0;
	struct tee_ioctl_version_data vers;

	memset(&vers, 0, sizeof(vers));

	fd = open(devname, O_RDWR);
	if (fd < 0)
		return -1;

	if (ioctl(fd, TEE_IOC_VERSION, &vers)) {
		EMSG("TEE_IOC_VERSION failed");
		goto err;
	}

	/* We can only handle GP TEEs */
	if (!(vers.gen_caps & TEE_GEN_CAP_GP))
		goto err;
	...
}
```

`TEEC_OpenSession`提供了从文件系统加载TA到TEE中，并打开TA-CA的安全通道session的功能。

libteec通过结构体`tee_ioctl_open_session_arg`和`tee_ioctl_param`传递session的信息

```c
struct tee_ioctl_open_session_arg {
	__u8 uuid[TEE_IOCTL_UUID_LEN];
	__u8 clnt_uuid[TEE_IOCTL_UUID_LEN];
	__u32 clnt_login;
	__u32 cancel_id;
	__u32 session;
	__u32 ret;
	__u32 ret_origin;
	__u32 num_params;
} __aligned(8);

struct tee_ioctl_param_memref {
	__u64 shm_offs;
	__u64 size;
	__s64 shm_id;
};

struct tee_ioctl_param_value {
	__u64 a;
	__u64 b;
	__u64 c;
};

struct tee_ioctl_param {
	__u64 attr;
	union {
		struct tee_ioctl_param_memref memref;
		struct tee_ioctl_param_value value;
	} u;
};
```



```c
TEEC_Result TEEC_OpenSession(TEEC_Context *ctx, TEEC_Session *session,
			const TEEC_UUID *destination,
			uint32_t connection_method, const void *connection_data,
			TEEC_Operation *operation, uint32_t *ret_origin)
{
	struct tee_ioctl_open_session_arg *arg = NULL;
	struct tee_ioctl_param *params = NULL;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t eorig = 0;
	int rc = 0;
	const size_t arg_size = sizeof(struct tee_ioctl_open_session_arg) +
				TEEC_CONFIG_PAYLOAD_REF_COUNT *
					sizeof(struct tee_ioctl_param);
	union {
		struct tee_ioctl_open_session_arg arg;
		uint8_t data[arg_size];
	} buf;
	struct tee_ioctl_buf_data buf_data;
	TEEC_SharedMemory shm[TEEC_CONFIG_PAYLOAD_REF_COUNT];

	memset(&buf, 0, sizeof(buf));
	memset(&shm, 0, sizeof(shm));
	memset(&buf_data, 0, sizeof(buf_data));
	
	(void)&connection_data;
	
	if (!ctx || !session) {
		eorig = TEEC_ORIGIN_API;
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}
	
	buf_data.buf_ptr = (uintptr_t)&buf;
	buf_data.buf_len = sizeof(buf);
	
	arg = &buf.arg;
	arg->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
	params = (struct tee_ioctl_param *)(arg + 1);
	
	uuid_to_octets(arg->uuid, destination);
	arg->clnt_login = connection_method;
	
	res = teec_pre_process_operation(ctx, operation, params, shm);
	if (res != TEEC_SUCCESS) {
		eorig = TEEC_ORIGIN_API;
		goto out_free_temp_refs;
	}
	
	rc = ioctl(ctx->fd, TEE_IOC_OPEN_SESSION, &buf_data);
	if (rc) {
		EMSG("TEE_IOC_OPEN_SESSION failed");
		eorig = TEEC_ORIGIN_COMMS;
		res = ioctl_errno_to_res(errno);
		goto out_free_temp_refs;
	}
	res = arg->ret;
	eorig = arg->ret_origin;
	if (res == TEEC_SUCCESS) {
		session->ctx = ctx;
		session->session_id = arg->session;
	}
	teec_post_process_operation(operation, params, shm);

out_free_temp_refs:
	teec_free_temp_refs(operation, shm);
out:
	if (ret_origin)
		*ret_origin = eorig;
	return res;
}
```

