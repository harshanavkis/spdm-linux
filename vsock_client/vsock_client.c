#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vm_sockets.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <net/sock.h>

#define VMADDR_PORT 31337
#define SERVER_CID 2 // Change to the actual CID of the server
#define BUF_SIZE 1024

static struct task_struct *vsock_client_thread;

static int vsock_client_fn(void *data) {
    struct socket *client_sock = NULL;
    char buffer[BUF_SIZE];
    struct sockaddr_vm sa_server = {0};
    int ret;
    const char *message = "Hello from VSOCK client\n";
    struct msghdr msg = {0};
    struct kvec iov;

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
        iov.iov_base = (void *)message;
        iov.iov_len = strlen(message);

        ret = kernel_sendmsg(client_sock, &msg, &iov, 1, strlen(message));
        if (ret < 0) {
	    // TODO: Handle cases when server disconnects
            pr_err("Failed to send message to vsock server\n");
        } else {
            pr_info("Message sent to server: %s\n", message);
        }

        // Receive back the message
        iov.iov_base = buffer;
        iov.iov_len = BUF_SIZE;
        ret = kernel_recvmsg(client_sock, &msg, &iov, 1, BUF_SIZE, 0);
        if (ret < 0) {
            pr_err("Failed to receive message on vsock client socket\n");
            break;
        } else if (ret == 0) {
            pr_info("Client disconnected\n");
            break;
        } else {
            buffer[ret] = '\0';
            pr_info("Received message: %s\n", buffer);
        }

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

