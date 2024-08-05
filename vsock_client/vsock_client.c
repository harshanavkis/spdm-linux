#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vm_sockets.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <net/sock.h>

#include <linux/mm.h>

#define VMADDR_PORT 31337
#define SERVER_CID 2 // Change to the actual CID of the server
#define BUF_SIZE 1024
#define OP_READ 1
#define OP_WRITE 2

static struct task_struct *vsock_client_thread;

static int vsock_client_fn(void *data) {
    struct socket *client_sock = NULL;
    // char buffer[BUF_SIZE];
    struct sockaddr_vm sa_server = {0};
    int ret;
    // const char *message = "Hello from VSOCK client\n";
    struct guest_message_header dev_access_header = {0};
    // dev_access_header.operation = OP_WRITE;
    // dev_access_header.length = strlen(message);
    struct msghdr msg = {0};
    struct kvec iov;

    // dev_access_header.operation = OP_READ;
    // dev_access_header.address = 0xfea00000;
    // dev_access_header.length = 4;

    dev_access_header.operation = OP_WRITE;
    dev_access_header.address = 0xfea00004;
    dev_access_header.length = 4;
    char write_data_buffer[] = { 0x00, 0x00, 0x00, 0x00 };

    ret = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &client_sock);
    if (ret < 0) {
        pr_err("Failed to create vsock client socket\n");
        return ret;
    }

    sa_server.svm_family = AF_VSOCK;
    sa_server.svm_cid = SERVER_CID;
    sa_server.svm_port = VMADDR_PORT;

    ret = kernel_connect(client_sock, (struct sockaddr *)&sa_server, sizeof(sa_server), 0);
    if (ret < 0) {
        pr_err("Failed to connect to vsock server\n");
        sock_release(client_sock);
        return ret;
    }

    pr_info("Connected to server on port %d\n", VMADDR_PORT);

    while (!kthread_should_stop()) {
        iov.iov_base = &dev_access_header;
        iov.iov_len = sizeof(struct guest_message_header);

        ret = kernel_sendmsg(client_sock, &msg, &iov, 1, iov.iov_len);
        if (ret < 0) {
	    // TODO: Handle cases when server disconnects
            pr_err("Failed to send message to vsock server\n");
        } else {
            pr_info("Message sent to server: %u\n", dev_access_header.operation);
        }

        // If OP_WRITE send data as well
        if (dev_access_header.operation == OP_WRITE)
        {
            iov.iov_base = (void *)write_data_buffer;
            iov.iov_len = dev_access_header.length;
            ret = kernel_sendmsg(client_sock, &msg, &iov, 1, iov.iov_len);
            if (ret < 0) {
            // TODO: Handle cases when server disconnects
                pr_err("Failed to send data to vsock server\n");
            } else {
                pr_info("Data sent to server: %u\n", dev_access_header.operation);
            }

            // Send read request to device
            dev_access_header.operation = OP_READ;
            iov.iov_base = &dev_access_header;
            iov.iov_len = sizeof(struct guest_message_header);

            ret = kernel_sendmsg(client_sock, &msg, &iov, 1, iov.iov_len);
            if (ret < 0) {
            // TODO: Handle cases when server disconnects
                pr_err("Failed to send message to vsock server\n");
            } else {
                pr_info("Message sent to server: %u\n", dev_access_header.operation);
            }

            // Check for inversion by EDU device
            iov.iov_base = (void *)write_data_buffer;
            iov.iov_len = dev_access_header.length;
            ret = kernel_recvmsg(client_sock, &msg, &iov, 1, iov.iov_len, 0);
            if (ret < 0) {
                pr_err("Failed to receive message on vsock client socket\n");
                break;
            } else if (ret == 0) {
                pr_info("Client disconnected\n");
                break;
            } else {
                pr_info("Received message: ");
                for (uint32_t i = 0; i < dev_access_header.length; i++)
                {
                    pr_info("%02X", ((uint8_t *)write_data_buffer)[i]);
                }
                pr_info("\n");
            }

            // Change back to write
            dev_access_header.operation = OP_WRITE;
        } else {
            // OP_READ
            char *read_data_buffer = kmalloc(dev_access_header.length, GFP_KERNEL);

            if (!read_data_buffer)
            {
                pr_err("kmalloc failed to allocate memory\n");
                return -ENOMEM; // Return an error code indicating out of memory
            }

            iov.iov_base = (void *) read_data_buffer;
            iov.iov_len = dev_access_header.length;

            ret = kernel_recvmsg(client_sock, &msg, &iov, 1, iov.iov_len, 0);

            if (ret < 0) {
                pr_err("Failed to receive message on vsock client socket\n");
                break;
            } else if (ret == 0) {
                pr_info("Client disconnected\n");
                break;
            } else {
                // read_data_buffer[ret] = '\0';
                // pr_info("Received message: %s\n", read_data_buffer);
                pr_info("Received message: ");
                for (uint32_t i = 0; i < dev_access_header.length; i++)
                {
                    pr_info("%02X", ((uint8_t *)read_data_buffer)[i]);
                }
                pr_info("\n");
            }

            kfree(read_data_buffer);
        }

        // dev_access_header.address += 1;

        // if (dev_access_header.operation == OP_WRITE)
        // {
        //     dev_access_header.operation = OP_READ;
        // } else {
        //     dev_access_header.operation = OP_WRITE;
        // }

        ssleep(5); // Send message every 10 seconds
    }

    sock_release(client_sock);
    return 0;
}

static int __init vsock_client_init(void) {
    vsock_client_thread = kthread_run(vsock_client_fn, NULL, "vsock_client_thread");
    if (IS_ERR(vsock_client_thread)) {
        pr_err("Failed to create vsock client thread\n");
        return PTR_ERR(vsock_client_thread);
    }

    pr_info("Vsock client module loaded\n");
    return 0;
}

static void __exit vsock_client_exit(void) {
    if (vsock_client_thread) {
        kthread_stop(vsock_client_thread);
    }

    pr_info("Vsock client module unloaded\n");
}

module_init(vsock_client_init);
module_exit(vsock_client_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Vsock Client Kernel Module");

