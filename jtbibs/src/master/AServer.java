package master;

import iaik.security.ssl.*;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.net.ServerSocket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.Thread.yield;

public abstract class AServer {
  List<Double> mServertimes = new ArrayList<>();
  /**
   * Server context.
   */
  protected SSLServerContext serverContext_;

  /**
   * Server socket.
   */
  protected SSLServerSocket serverSocket_;

  /**
   * Checks if the server is running.
   */
  protected boolean isRunning_;

  /**
   * The port to listen on.
   */
  protected int port_;
  /**
   * tell when allowed to stop
   */
  protected Semaphore sem = new Semaphore(1);

  /**
   * Starts the Server.
   */
  public void start() throws IOException {
    ThreadMXBean threadMXBean = ManagementFactory.getThreadMXBean(); //for CPU time

    if (serverSocket_ == null) {
      // create SSLServerSocket
      serverSocket_ = new SSLServerSocket(port_, serverContext_);
    }
    System.out.println("Listening for HTTPS connections on port " + port_ + "...");
    isRunning_ = true;
    // for each request create a new Thread
    while (isRunning_) {
      SSLSocket socket = null;
      long start = 0;
      try {
        socket = (SSLSocket) serverSocket_.accept();
        sem.acquire();
        start = threadMXBean.getThreadCpuTime(Thread.currentThread().getId());
        socket.setSoTimeout(1000 * 30);
        System.out.println("Accepted connection from " + socket.getInetAddress());
        socket.getInputStream(); //starts handshake
      } catch (InterruptedException | NullPointerException e) {/*ignore*/
      } catch (SocketException e) {
        if (!e.getMessage().equals("Socket closed")) // happens always as accept waits and we shutdown server...
          throw e;
      } finally
     {
      System.out.println("Server closing socket.");
       long end = threadMXBean.getThreadCpuTime(Thread.currentThread().getId());
       double servertime = (end - start) / 1000000.0;
       mServertimes.add(servertime);
       System.out.println("servertime[ms]: " + servertime);
      if (socket != null && !socket.isClosed())
        socket.close();
      sem.release();
    }
  }

}

  /**
   * Stops the server.
   */
  public void stop() {
    try {
      sem.acquire();
      if (serverSocket_ != null) {
        ServerSocket serverSocket = serverSocket_;
        serverSocket_ = null;
        try {
          serverSocket.close();
        } catch (Exception ex) {
        }
      }
      isRunning_ = false;
      serverSocket_ = null;
    } catch (InterruptedException e) {
    } finally {
      sem.release();
      System.out.println("Means servertime: " + mServertimes.stream().mapToDouble(d -> d).average().orElse(0.0));
      System.out.println("Median servertime: " + mServertimes.stream().mapToDouble(d -> d).sorted().toArray()[mServertimes.size()/2]);
    }
  }
}
