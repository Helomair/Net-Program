#include <vector>
#include <queue>
#include <stdio.h>
#include <math.h>
#define MIDDLE -1
#define DIRACTION -2
#define INTERSECTION -3
#define SELECT 1
#define DELETE 0

static double pi = 4 * atan(1.0);
struct coordinate {
    int id;
    double x, y;
    //Distance square
    double operator ^ (struct coordinate neighbor) {
        return (x - neighbor.x) * (x - neighbor.x) + (y - neighbor.y) * (y - neighbor.y);
    }
    //equal operator
    void operator = (struct coordinate neighbor) {
        id = neighbor.id;
        x = neighbor.x;
        y = neighbor.y;
    }
    //find tje middle point
    struct coordinate operator | (struct coordinate neighbor) {
        struct coordinate trans;
        trans.id = MIDDLE;
        trans.x = (x + neighbor.x) / 2;
        trans.y = (y + neighbor.y) / 2;
        return trans;
    }
    //find the vector of two points
    struct coordinate operator ->* (struct coordinate via) {
        struct coordinate trans;
        trans.id = DIRACTION;
        trans.x = (via.x - x);
        trans.y = (via.y - y);
        return trans;
    }
    //define is the outer product in or out
    bool outer_product (struct coordinate via) {
        if ( x*via.y-y*via.x > 0 )
            return true;
        else
            return false;
    }
    //find the inner product
    double inner_product (struct coordinate via)    {
        return x * via.x + y * via.y;
    }
    //find the right hand angle
    double right_hand_angle (struct coordinate via)  {
        double angle = acos(inner_product(via) / (product()*via.product()));
        if (abs(inner_product(via) / (product()*via.product())) > 0.9999 && abs(inner_product(via) / (product()*via.product())) < 1.0001 )
            return 360;
        if (outer_product(via))
            return (pi-angle)/pi*180;
        else
            return (pi+angle)/pi*180;
    }
    double product () {
        return sqrt(x * x + y * y);
    }
};

//line ab and line cd ,return intersection point. 
struct coordinate get_inte (struct coordinate a,struct coordinate b,struct coordinate c,struct coordinate d)   {
    struct coordinate intersection;
    double m = (a.y - b.y) / (a.x - b.x);
    double y6 = m * (c.x - a.x) + a.y;
    double y5 = m * (d.x - a.x) + a.y;

    intersection.x = c.x + (d.x - c.x) * (y6 - c.y) / (d.y - y5 + y6 - c.y);
    intersection.y = m * (intersection.x - a.x) + a.y;
    intersection.id = INTERSECTION;
    return intersection;
}

//the sending package
struct Package {
    struct coordinate source,intersection,distination;
    struct coordinate diraction;
    int next_hop, last_hop;
    std::queue <int> path;
};

class Node {
    friend void run(int source, int distination, std::vector<class Node> &node);

  public:
        Node(struct coordinate tr2) {
            location = tr2;
        }
        void push_nearby (struct coordinate a) {
            nearby_node.push_back(a);
        }
        void print() {
            printf("[%d](%.3lf,%.3lf)\n\t",location.id,location.x,location.y);
            printf("nearby_node:");
            for (auto i : nearby_node)
                printf("%d ", i.id);
            printf("\n\tcutoff_node:");
            for (auto i : cutoff_node)
                printf("%d ", i.id);
            /*printf("\n\tpackage_queue:");
            for (int i = 0; i < package_queue.size();i++) {
                struct Package package = package_queue.front();
                printf("[%d %d]",  package.last_hop,package.next_hop);
                package_queue.pop();
                package_queue.push(package);
                }*/
            printf("\n\t\t\tsend:");
            for (auto i : send_queue) {
                struct Package package = send_queue.front();
                printf("[%d %d]",  package.last_hop,package.next_hop);
                send_queue.pop();
                send_queue.push(package);
            }
            printf("\n");
        }
        // if the circle between me and the other node has another node -> delete the other node
        void flattening() {
            struct coordinate middle;
            double radius;
            int table[nearby_node.size()];

            for (int i = 0; i < nearby_node.size(); i++)    {
                table[i] = SELECT;
                middle = location | nearby_node[i];
                radius = middle ^ location;
                for (int j = 0; j < nearby_node.size(); j++)    {
                    if (i!=j && radius > ( nearby_node[j] ^ middle ) )  {
                        table[i] = DELETE;
                        break;
                    }
                }
            }
            for (int i = 0; i < nearby_node.size(); i++)
                if (table[i] == SELECT)
                    cutoff_node.push_back(nearby_node[i]);
        }
        //accept the package from other node
        void receive(struct Package package){
            package_queue.push(package);
        }
        //check if the backage are on the right way
        void check() {
            while (package_queue.size()!=0) {
                //printf("((%d))\n", location.id);
                struct Package package = package_queue.front();
                package_queue.pop();
                if (package.next_hop == location.id) 
                    modify(package);
            }
        }
        //determine the correct next hop
        void modify(struct Package package) {
            //printf("%d %d\n", location.id, package.distination.id);
            if (location.id == package.distination.id) {
                package.path.push(location.id);
                print_flow(package);
                return;
            }
            int min_node;
            double angle,min_angle=361;
            for (int i = 0; i < cutoff_node.size(); i++) {
                angle = package.diraction.right_hand_angle(location->*cutoff_node[i]);
                if (angle <0.00001) angle =360;
                //printf("\n![%d,%d](%lf,%lf)   [(%d,%d) , %lf]", package.last_hop, location.id,package.diraction.x,package.diraction.y,package.next_hop, cutoff_node[i].id, angle);
                if ( angle < min_angle ) {
                    min_angle = angle;
                    min_node = i;   
                }
            }
            //printf("\t\t%d\n", between(package.distination, package.intersection, location, cutoff_node[min_node]));
            if ( between(package.distination,package.intersection,location,cutoff_node[min_node]) ) {
                package.intersection = get_inte(package.distination, package.intersection, location, cutoff_node[min_node]);
                package.diraction = package.intersection ->* location;
                if (package.diraction.outer_product(package.intersection ->* package.source)!=1) {
                modify(package);
                return;
                }
            }
            
            package.next_hop = cutoff_node[min_node].id;
            package.last_hop = location.id;
            package.diraction = location ->* cutoff_node[min_node];
            package.path.push(location.id);
            send_queue.push(package);
        }
        //initialize a new package from source
        void make_package (struct coordinate distination) {
            struct Package package;
            package.source = location;
            package.distination = distination;
            package.intersection = location;
            package.last_hop = distination.id;
            package.next_hop = location.id;
            package.diraction = distination ->* location;

            for (int i = 0; i < cutoff_node.size(); i++) 
                if (distination.id == cutoff_node[i].id)    {
                    package.path.push(location.id);
                    package.last_hop = location.id;
                    package.next_hop = distination.id;
                    package.diraction = location->* distination;
                    send_queue.push(package);
                    return;
                }
            receive(package);
        }

        //return the information of this node
        struct coordinate info () {
            return location;
        }

        void print_flow (struct Package package) {
            while (package.path.size()){
                printf("%d ", package.path.front());
                package.path.pop();
            }
        }

      private:
        std::queue<struct Package> send_queue;
        std::vector<struct coordinate> nearby_node;
        std::vector<struct coordinate> cutoff_node;
        std::queue<struct Package> package_queue;
        struct coordinate location;
        //determine if the new intersection is between the old intersection and distination or not
        bool between (struct coordinate a,struct coordinate b,struct coordinate c,struct coordinate d)    {
            struct coordinate intersection = get_inte(a,b,c,d);
            double aa, bb, cc, dd;
            if (a.x > b.x)      { aa = a.x;bb = b.x; }
            else { aa=b.x; bb=a.x;}
            if (c.x > d.x)      { cc = c.x;dd = d.x; }
            else { cc=d.x; dd=c.x;}

            if (intersection.x < aa - 0.0001 && intersection.x > bb + 0.0001 && intersection.x < cc - 0.0001 && intersection.x >dd + 0.0001 )
                return true;
            else
                return false;
        }

};

//run the test case
void run (int source,int distination,std::vector<class Node> &node) {
    node[source].make_package(node[distination].info());
    int n = 200;
    while (n--) {
    for (auto i : node)   
        i.check();
   
    for (int i = 0; i < node.size(); i++)
            while (node[i].send_queue.size()!=0) {
                struct Package package = node[i].send_queue.front();
                node[i].send_queue.pop();
                for (int j = 0; j < node[i].nearby_node.size(); j++)    {
                    int now = node[i].nearby_node[j].id;
                    node[now].receive(package);
                }
        }
    }
    printf("\n");
}

------WebKitFormBoundaryb2lfNkCjw2oraKaS--
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             