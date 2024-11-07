from flask import Flask, render_template, url_for, redirect, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os
from flask_restful import Api, Resource



project_path = '/Users/chinmaybhobe/Documents/Flask_tutorial'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(project_path, "database.db")}'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Create a Flask-RESTful API
api = Api(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Categories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Category_name = db.Column(db.String(20), nullable=False, unique=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Product_name = db.Column(db.String(50), nullable=False, unique=True)
    cat_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    units_id = db.Column(db.Integer,db.ForeignKey('unit.id'), nullable=False)
    rate_per_unit = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    category = db.relationship('Categories', backref=db.backref('products', lazy=True))
    unit = db.relationship('Unit', backref=db.backref('products', lazy=True))

class Unit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)

class Orders(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)

    # Relationship with User table
    user = db.relationship('User', backref=db.backref('orders', lazy=True))

class Sold_Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity_sold = db.Column(db.Integer, nullable=False)

    # Relationship with Orders table
    order = db.relationship('Orders', backref=db.backref('sold_products', lazy=True))

    # Relationship with Product table
    product = db.relationship('Product', backref=db.backref('sold_products', lazy=True))






class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

#--------------------------LOGIN/REGIDTRATION-----------------------------------------------------

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard_user'))
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('That username already exists. Please choose a different one.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration and Login successful!', 'success')
            return redirect(url_for('login'))
    
    
    return render_template('register.html', form=form)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    form = LoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin:
            if admin.password == form.password.data:
                login_user(admin)
                return redirect(url_for('dashboard_admin'))
    return render_template('admin_login.html', form=form)




#--------------------------------ADMIN--------------------------------------------

@app.route('/dashboard_admin', methods=['GET', 'POST'])
@login_required
def dashboard_admin():
    categories = Categories.query.all()
    products = Product.query.all()
    units = Unit.query.all()
    
    return render_template('admin_dashboard.html', categories=categories, products=products, category=None)


# CREATE NEW CATEGORY
@app.route('/dashboard_admin/create_category', methods=['GET','POST'])
@login_required
def create_category():
    if request.method == 'POST':
        name = request.form['category']

        # Check if the category name already exists in the database
        existing_category = Categories.query.filter_by(Category_name=name).first()
        if existing_category:
            flash(f'Category "{name}" already exists', 'danger')
        else:
            category = Categories(Category_name=name)
            db.session.add(category)
            db.session.commit()

            flash(f'Category "{name}" created successfully', 'success')

        return redirect(url_for('dashboard_admin'))
    
    return render_template('admin_dashboard.html')


# UPDATE CATAGORY NAME
@app.route('/dashboard_admin/update_category_name/<int:category_id>', methods=['POST'])
@login_required
def update_category_name(category_id):
    category = Categories.query.get_or_404(category_id)
    new_name = request.form.get('category_name')

    # Update the category name in the database
    category.Category_name = new_name
    db.session.commit()

    flash("Category name updated successfully", "success")
    return redirect(url_for('dashboard_admin'))


# DELETE FULL CATAGORY
@app.route('/dashboard_admin/delete_category/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    category = Categories.query.get_or_404(category_id)
    
    # Delete all the products under this category
    for product in category.products:
        db.session.delete(product)
    
    # Delete the category
    db.session.delete(category)
    db.session.commit()

    flash("Category and all its products have been deleted successfully", "success")
    return redirect(url_for('dashboard_admin'))



# UPDATE PRODUCT DETAILS
@app.route('/dashboard_admin/update_product/<int:product_id>', methods=['GET', 'POST'])
def update_product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        # Get the entered HTML form data
        category_name = request.form.get('category')
        unit_name = request.form.get('unit')
        product_name = request.form.get('product_name')
        rate_per_unit = request.form.get('rate_per_unit')
        quantity = request.form.get('quantity')

        category = Categories.query.filter_by(Category_name=category_name).first()
        unit = Unit.query.filter_by(name=unit_name).first()

        if category and unit:
            # Update the existing Product object with the retrieved IDs
            product.Product_name = product_name
            product.cat_id = category.id
            product.units_id = unit.id
            product.rate_per_unit = rate_per_unit
            product.quantity = quantity

            # Commit the changes to the database
            db.session.commit()

            flash('Product details updated successfully', 'success')

            # Redirect to a success page or perform any other necessary actions
            return redirect(url_for('dashboard_admin'))

    categories = Categories.query.all()
    units = Unit.query.all()
    return render_template('update_product.html', product=product, categories=categories, units=units)

# DELETE ENTIRE PRODUCT 
@app.route('/dashboard_admin/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Delete the category
    db.session.delete(product)
    db.session.commit()

    flash("The Product deleted successfully", "success")
    return redirect(url_for('dashboard_admin'))



# CREATES NEW PRODUCT IN A CATAGORY
@app.route('/dashboard_admin/create_product', methods=['GET', 'POST'])
def create_product():
    if request.method == 'POST':
        # Get the entered HTML form data
        category_name = request.form.get('category')
        unit_name = request.form.get('unit')
        product_name = request.form.get('product_name')
        rate_per_unit = request.form.get('rate_per_unit')
        quantity = request.form.get('quantity')

        # Retrieve the category and unit objects based on the selected names
        # Basically this gets the respective Ids instead of name because of first()
        category = Categories.query.filter_by(Category_name=category_name).first()
        unit = Unit.query.filter_by(name=unit_name).first()

        if category and unit:
            # Check if the product name already exists in the database
            existing_product = Product.query.filter_by(Product_name=product_name).first()
            if existing_product:
                flash(f'Product "{product_name}" already exists, Kindly update its details if needed', 'danger')
            else:
                # FOREIGN KEY This is how I relate my tables' primary key to my other tables
                # Create a new Product object with the retrieved IDs
                product = Product(Product_name=product_name, cat_id=category.id, units_id=unit.id,
                                  rate_per_unit=rate_per_unit, quantity=quantity)

                # Add the product to the database
                db.session.add(product)
                db.session.commit()

                flash(f'Product "{product_name}" added successfully', 'success')

            # Redirect to a success page or perform any other necessary actions
            return redirect(url_for('dashboard_admin'))

    categories = Categories.query.all()
    units = Unit.query.all()

    return render_template('create_product.html', categories=categories, units=units)





#----------------------------USER-----------------------------------------------

@app.route('/dashboard_user/search_products', methods=['GET'])
def search_products():
    search_term = request.args.get('search_term')

    # Check if the search term corresponds to a category
    category = Categories.query.filter_by(Category_name=search_term).first()

    if category:
        # If the search term is a category, retrieve all products within that category
        products = Product.query.filter_by(cat_id=category.id).all()
    else:
        # If the search term is not a category, perform the regular product search
        products = Product.query.filter(Product.Product_name.contains(search_term)).all()

        # If no products are found, check if the search term is a substring of any category name
        if not products:
            categories = Categories.query.filter(Categories.Category_name.contains(search_term)).all()
            # Retrieve all products within the found categories
            products = [product for category in categories for product in category.products]

    categories = Categories.query.all()

    return render_template('dashboard_user.html', products=products, categories=categories)




@app.route('/dashboard_user/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    # Retrieve the product by ID
    product = Product.query.get_or_404(product_id)

    # Generate a unique key for the user's cart using their ID
    user_cart_key = f'user_cart_{current_user.id}'

    # Get the current cart from the session or initialize an empty list
    cart = session.get(user_cart_key, [])

    # Check if the product is already in the cart
    for item in cart:
        if item['id'] == product.id:
            flash(f'{product.Product_name} is already in your cart. Kindly Update the product quantity in your Shopping cart.', 'danger')
            return redirect(url_for('dashboard_user'))

    # Append the product to the cart with quantity 1 and total price
    cart.append({
        'id': product.id,
        'name': product.Product_name,
        'price': product.rate_per_unit,
        'quantity': 1,
        'total_price': product.rate_per_unit  # Initialize total price with the price of one item
    })

    # Store the updated cart back in the session
    session[user_cart_key] = cart

    flash(f'{product.Product_name} added to cart', 'success')
    return redirect(url_for('dashboard_user'))






@app.route('/cart', methods=['GET'])
@login_required
def view_cart():
    # Generate a unique key for the user's cart using their ID
    user_cart_key = f'user_cart_{current_user.id}'

    # Retrieve the cart from the session
    cart = session.get(user_cart_key, [])
    total_amount = sum(item.get('total_price', item['price'] * item.get('quantity', 1)) for item in cart)

    return render_template('cart.html', cart=cart, total_amount=total_amount)


@app.route('/cart/update_quantity/<int:product_id>', methods=['POST'])
@login_required
def update_quantity(product_id):
    # Retrieve the product by ID
    product = Product.query.get_or_404(product_id)

    # Generate a unique key for the user's cart using their ID
    user_cart_key = f'user_cart_{current_user.id}'

    # Get the current cart from the session or initialize an empty list
    cart = session.get(user_cart_key, [])

    # Update the quantity for the specific product in the cart
    new_quantity = int(request.form.get('quantity'))
    for item in cart:
        if item['id'] == product.id:
            item['quantity'] = new_quantity
            if 'total_price' in item:
                item['total_price'] = product.rate_per_unit * new_quantity  # Recalculate the total price
            break

    # Store the updated cart back in the session
    session[user_cart_key] = cart
 
    flash(f'{product.Product_name} quantity updated to {new_quantity}', 'success')
    return redirect(url_for('view_cart'))

@app.route('/cart/remove_from_cart/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    # Retrieve the product by ID
    product = Product.query.get_or_404(product_id)

    # Generate a unique key for the user's cart using their ID
    user_cart_key = f'user_cart_{current_user.id}'

    # Get the current cart from the session or initialize an empty list
    cart = session.get(user_cart_key, [])

    # Remove the specific product from the cart
    cart = [item for item in cart if item['id'] != product.id]

    # Store the updated cart back in the session
    session[user_cart_key] = cart

    flash(f'{product.Product_name} removed from cart', 'success')
    return redirect(url_for('view_cart'))


@app.route('/cart/purchase', methods=['POST'])
@login_required
def purchase():
    # Generate a unique key for the user's cart using their ID
    user_cart_key = f'user_cart_{current_user.id}'

    # Retrieve the cart from the session
    cart = session.get(user_cart_key, [])

    # Calculate the total amount of the order
    total_amount = sum(item.get('total_price', item['price'] * item.get('quantity', 1)) for item in cart)

    # Update the product quantities in the database and check for insufficient stock
    for item in cart:
        product_id = item['id']
        product = Product.query.get_or_404(product_id)
        new_quantity = product.quantity - item.get('quantity', 1)
        if new_quantity < 0:
            flash(f'Insufficient stock for {product.Product_name}', 'danger')
            return redirect(url_for('view_cart'))
        product.quantity = new_quantity

    # Create a new order in the Orders table
    new_order = Orders(user_id=current_user.id, total_amount=total_amount)
    db.session.add(new_order)

    # Flush the session to insert the new_order into the database
    db.session.flush()

    # Populate the Sold_Products table for each item in the cart
    for item in cart:
        new_sold_product = Sold_Products(order_id=new_order.id, product_id=item['id'], quantity_sold=item.get('quantity', 1))
        db.session.add(new_sold_product)

    # Commit the changes to the database
    db.session.commit()

    # Clear the cart after purchase
    session[user_cart_key] = []

    # Render the purchase details page
    return render_template('purchase_done.html', current_user=current_user, cart=cart, total_amount=total_amount, order_id=new_order.id )





@app.route('/dashboard_user', methods=['GET', 'POST'])
@login_required
def dashboard_user():

    
    categories = Categories.query.all()

    return render_template('dashboard_user.html', categories=categories)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))






#---------------------------API--------------------------------



# Create a resource To get Top 5 USERS
class SummaryResource(Resource):
    @login_required
    def get(self):
        summary_data = self.get_summary_data()
        return {'summary': summary_data}

    def get_summary_data(self):
        summary_data = []

        # Query the database to get the total purchases for each user
        users = User.query.all()
        for user in users:
            total_orders = len(user.orders)
            total_purchases = sum(order.total_amount for order in user.orders)
            summary_data.append(
                {'username': user.username, 
                 'total_purchases': total_purchases, 
                 'total_orders': total_orders})

        # Sort the summary_data in descending order based on 'total_purchases'
        sorted_summary_data_purchases = sorted(summary_data, key=lambda x: x['total_purchases'], reverse=True)
        sorted_summary_data_orders = sorted(summary_data, key=lambda x: x['total_orders'], reverse=True)
        
        return sorted_summary_data_purchases[:5], sorted_summary_data_orders[:5]
    
# Add the SummaryResource to the API with the appropriate URL
api.add_resource(SummaryResource, '/api/summary')


# Create a resource To get Top 5 Products
class TopProductsResource(Resource):
    @login_required
    def get(self):
        top_product=self.get_top_product()
        return {'top_selling': top_product}
    
    def get_top_product(self):
        top_product = []

        products = Product.query.all()
        for product in products:
            total_quantity_sold = sum(sold_product.quantity_sold for sold_product in product.sold_products)
            top_product.append(
                {'product': product.Product_name,
                  'quantity_sold': total_quantity_sold
                })
        
        
        sorted_top_products = sorted(top_product, key=lambda x: x['quantity_sold'], reverse=True)

        return sorted_top_products[:10]  # Return only the top 5 products     


api.add_resource(TopProductsResource, '/api/top_products')

# Create a resource to get Products with Low Quantity
class LowQuantityProductsResource(Resource):
    @login_required
    def get(self):
        low_quantity_products = self.get_low_quantity_products()
        return {'low_quantity_products': low_quantity_products}
    
    def get_low_quantity_products(self):
        low_quantity_products = []

        products = Product.query.filter(Product.quantity < 5).all()
        for product in products:
            low_quantity_products.append(
                {'product': product.Product_name,
                 'available_quantity': product.quantity
                })
        
        return low_quantity_products

api.add_resource(LowQuantityProductsResource, '/api/low_quantity_products')

@app.route('/summary')
@login_required
def summary():
    response_summary = app.test_client().get('/api/summary')
    response_top_products = app.test_client().get('/api/top_products')
    response_low_quantity_products = app.test_client().get('/api/low_quantity_products')
    
    if response_summary.status_code == 200 and response_top_products.status_code == 200 and response_low_quantity_products.status_code == 200:
        summary_data = response_summary.json.get('summary', [])
        top_products_data = response_top_products.json.get('top_selling', [])
        low_quantity_products_data = response_low_quantity_products.json.get('low_quantity_products', [])
        
        return render_template('summary.html', summary_data=summary_data, top_products_data=top_products_data,low_quantity_products_data=low_quantity_products_data)
    else:
        flash('Failed to fetch summary data or top products data or low quantity products data', 'danger')
        return redirect(url_for('dashboard_admin'))





if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)




