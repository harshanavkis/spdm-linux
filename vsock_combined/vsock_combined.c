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

static struct task_struct *vsock_server_thread;
static struct task_struct *vsock_client_thread;

static int vsock_client_handler(void *data) {
    struct socket *client_sock = (struct socket *)data;
    char buffer[BUF_SIZE];
    struct msghdr msg = {0};
    struct kvec iov;
    int len;

    while (!kthread_should_stop()) {
        iov.iov_base = buffer;
        iov.iov_len = BUF_SIZE;

        len = kernel_recvmsg(client_sock, &msg, &iov, 1, BUF_SIZE, 0);
        if (len < 0) {
            pr_err("Failed to receive message on vsock client socket\n");
            break;
        } else if (len == 0) {
            pr_info("Client disconnected\n");
            break;
        } else {
            buffer[len] = '\0';
            pr_info("Received message: %s\n", buffer);
        }
    }

    sock_release(client_sock);
    return 0;
}

static int vsock_server_fn(void *data) {
    struct socket *server_sock = NULL;
    struct socket *client_sock = NULL;
    struct sockaddr_vm sa_listen = {0};
    int ret;

    ret = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &server_sock);
    if (ret < 0) {
        pr_err("Failed to create vsock server socket\n");
        return ret;
    }

    sa_listen.svm_family = AF_VSOCK;
    sa_listen.svm_cid = VMADDR_CID_ANY;
    sa_listen.svm_port = VMADDR_PORT;

    ret = kernel_bind(server_sock, (struct sockaddr *)&sa_listen, sizeof(sa_listen));
    if (ret < 0) {
        pr_err("Failed to bind vsock server socket\n");
        sock_release(server_sock);
        return ret;
    }

    ret = kernel_listen(server_sock, 1);
    if (ret < 0) {
        pr_err("Failed to listen on vsock server socket\n");
        sock_release(server_sock);
        return ret;
    }

    pr_info("Vsock server listening on port %d\n", VMADDR_PORT);

    while (!kthread_should_stop()) {
        ret = kernel_accept(server_sock, &client_sock, 0);
        if (ret < 0) {
            pr_err("Failed to accept connection on vsock server socket\n");
            continue;
        }

        pr_info("Accepted a new connection\n");

        kthread_run(vsock_client_handler, client_sock, "vsock_client_handler");
    }

    sock_release(server_sock);

    return 0;
}

static int vsock_client_fn(void *data) {
    struct socket *client_sock = NULL;
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
	    // TODO: Handle cases when client disconnects
            pr_err("Failed to send message to vsock server\n");
        } else {
            pr_info("Message sent to server: %s\n", message);
        }

        ssleep(10); // Send message every 10 seconds
    }

    sock_release(client_sock);
    return 0;
}

static int __init vsock_combined_init(void) {
    vsock_server_thread = kthread_run(vsock_server_fn, NULL, "vsock_server_thread");
    if (IS_ERR(vsock_server_thread)) {
        pr_err("Failed to create vsock server thread\n");
        return PTR_ERR(vsock_server_thread);
    }

    vsock_client_thread = kthread_run(vsock_client_fn, NULL, "vsock_client_thread");
    if (IS_ERR(vsock_client_thread)) {
        pr_err("Failed to create vsock client thread\n");
        kthread_stop(vsock_server_thread);
        return PTR_ERR(vsock_client_thread);
    }

    pr_info("Vsock combined client-server module loaded\n");
    return 0;
}

static void __exit vsock_combined_exit(void) {
    if (vsock_server_thread) {
        kthread_stop(vsock_server_thread);
    }

    if (vsock_client_thread) {
        kthread_stop(vsock_client_thread);
    }

    pr_info("Vsock combined client-server module unloaded\n");
}

module_init(vsock_combined_init);
module_exit(vsock_combined_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Vsock Combined Client-Server Kernel Module");

