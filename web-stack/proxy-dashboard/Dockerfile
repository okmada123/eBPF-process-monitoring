FROM nginx:latest

COPY index.html /usr/share/nginx/html/index.html
COPY default.conf /etc/nginx/conf.d/

EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
